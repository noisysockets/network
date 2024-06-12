//go:build linux

// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 The Noisy Sockets Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Portions of this file are based on code originally from wireguard-go,
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is furnished to do
 * so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package tun

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/noisysockets/netstack/pkg/tcpip"
	"github.com/noisysockets/netstack/pkg/tcpip/checksum"
	"github.com/noisysockets/netstack/pkg/tcpip/header"
	"github.com/noisysockets/network"
	"golang.org/x/sys/unix"
)

// tcpFlowKey represents the key for a TCP flow.
type tcpFlowKey struct {
	srcAddr, dstAddr tcpip.Address
	srcPort, dstPort uint16
	rxAck            uint32 // varying ack values should not be coalesced. Treat them as separate flows.
	isV6             bool
}

// tcpGROTable holds flow and coalescing information for the purposes of TCP GRO.
type tcpGROTable struct {
	itemsByFlow map[tcpFlowKey][]tcpGROItem
	itemsPool   [][]tcpGROItem
}

func newTCPGROTable(batchSize int) *tcpGROTable {
	t := &tcpGROTable{
		itemsByFlow: make(map[tcpFlowKey][]tcpGROItem, batchSize),
		itemsPool:   make([][]tcpGROItem, batchSize),
	}
	for i := range t.itemsPool {
		t.itemsPool[i] = make([]tcpGROItem, 0, batchSize)
	}
	return t
}

func newTCPFlowKey(pkt []byte) (key tcpFlowKey) {
	var nextHdr int

	ipVersion := pkt[0] >> 4
	if ipVersion == header.IPv4Version {
		ipHdr := header.IPv4(pkt)
		nextHdr = int(ipHdr.HeaderLength())

		key.srcAddr = ipHdr.SourceAddress()
		key.dstAddr = ipHdr.DestinationAddress()
	} else {
		ipHdr := header.IPv6(pkt)
		nextHdr = int(ipHdr.NextHeader())

		key.srcAddr = ipHdr.SourceAddress()
		key.dstAddr = ipHdr.DestinationAddress()
		key.isV6 = true
	}

	tcpHdr := header.TCP(pkt[nextHdr:])
	key.srcPort = tcpHdr.SourcePort()
	key.dstPort = tcpHdr.DestinationPort()
	key.rxAck = tcpHdr.AckNumber()

	return key
}

// lookupOrInsert looks up a flow for the provided packet and metadata,
// returning the packets found for the flow, or inserting a new one if none
// is found.
func (t *tcpGROTable) lookupOrInsert(pkt []byte, tcphOffset, tcphLen, bufsIndex int) ([]tcpGROItem, bool) {
	key := newTCPFlowKey(pkt)
	items, ok := t.itemsByFlow[key]
	if ok {
		return items, ok
	}
	// TODO: insert() performs another map lookup. This could be rearranged to avoid.
	t.insert(pkt, tcphOffset, tcphLen, bufsIndex)
	return nil, false
}

// insert an item in the table for the provided packet and packet metadata.
func (t *tcpGROTable) insert(pkt []byte, tcphOffset, tcphLen, bufsIndex int) {
	key := newTCPFlowKey(pkt)
	item := tcpGROItem{
		key:       key,
		bufsIndex: uint16(bufsIndex),
		gsoSize:   uint16(len(pkt[tcphOffset+tcphLen:])),
		iphLen:    uint8(tcphOffset),
		tcphLen:   uint8(tcphLen),
		sentSeq:   binary.BigEndian.Uint32(pkt[tcphOffset+4:]),
		pshSet:    pkt[tcphOffset+header.TCPFlagsOffset]&uint8(header.TCPFlagPsh) != 0,
	}
	items, ok := t.itemsByFlow[key]
	if !ok {
		items = t.newItems()
	}
	items = append(items, item)
	t.itemsByFlow[key] = items
}

func (t *tcpGROTable) updateAt(item tcpGROItem, i int) {
	items := t.itemsByFlow[item.key]
	items[i] = item
}

func (t *tcpGROTable) deleteAt(key tcpFlowKey, i int) {
	items := t.itemsByFlow[key]
	items = append(items[:i], items[i+1:]...)
	t.itemsByFlow[key] = items
}

// tcpGROItem represents bookkeeping data for a TCP packet during the lifetime
// of a GRO evaluation across a vector of packets.
type tcpGROItem struct {
	key       tcpFlowKey
	sentSeq   uint32 // the sequence number
	bufsIndex uint16 // the index into the original bufs slice
	numMerged uint16 // the number of packets merged into this item
	gsoSize   uint16 // payload size
	iphLen    uint8  // ip header len
	tcphLen   uint8  // tcp header len
	pshSet    bool   // psh flag is set
}

func (t *tcpGROTable) newItems() []tcpGROItem {
	var items []tcpGROItem
	items, t.itemsPool = t.itemsPool[len(t.itemsPool)-1], t.itemsPool[:len(t.itemsPool)-1]
	return items
}

func (t *tcpGROTable) reset() {
	for k, items := range t.itemsByFlow {
		items = items[:0]
		t.itemsPool = append(t.itemsPool, items)
		delete(t.itemsByFlow, k)
	}
}

// udpFlowKey represents the key for a UDP flow.
type udpFlowKey struct {
	srcAddr, dstAddr tcpip.Address
	srcPort, dstPort uint16
	isV6             bool
}

// udpGROTable holds flow and coalescing information for the purposes of UDP GRO.
type udpGROTable struct {
	itemsByFlow map[udpFlowKey][]udpGROItem
	itemsPool   [][]udpGROItem
}

func newUDPGROTable(batchSize int) *udpGROTable {
	u := &udpGROTable{
		itemsByFlow: make(map[udpFlowKey][]udpGROItem, batchSize),
		itemsPool:   make([][]udpGROItem, batchSize),
	}
	for i := range u.itemsPool {
		u.itemsPool[i] = make([]udpGROItem, 0, batchSize)
	}
	return u
}

func newUDPFlowKey(pkt []byte) (key udpFlowKey) {
	var nextHdr int

	ipVersion := pkt[0] >> 4
	if ipVersion == header.IPv4Version {
		ipHdr := header.IPv4(pkt)
		nextHdr = int(ipHdr.HeaderLength())

		key.srcAddr = ipHdr.SourceAddress()
		key.dstAddr = ipHdr.DestinationAddress()
	} else {
		ipHdr := header.IPv6(pkt)
		nextHdr = int(ipHdr.NextHeader())

		key.srcAddr = ipHdr.SourceAddress()
		key.dstAddr = ipHdr.DestinationAddress()
		key.isV6 = true
	}

	udpHdr := header.UDP(pkt[nextHdr:])
	key.srcPort = udpHdr.SourcePort()
	key.dstPort = udpHdr.DestinationPort()

	return key
}

// lookupOrInsert looks up a flow for the provided packet and metadata,
// returning the packets found for the flow, or inserting a new one if none
// is found.
func (u *udpGROTable) lookupOrInsert(pkt []byte, udphOffset, bufsIndex int) ([]udpGROItem, bool) {
	key := newUDPFlowKey(pkt)
	items, ok := u.itemsByFlow[key]
	if ok {
		return items, ok
	}
	// TODO: insert() performs another map lookup. This could be rearranged to avoid.
	u.insert(pkt, udphOffset, bufsIndex, false)
	return nil, false
}

// insert an item in the table for the provided packet and packet metadata.
func (u *udpGROTable) insert(pkt []byte, udphOffset, bufsIndex int, cSumKnownInvalid bool) {
	key := newUDPFlowKey(pkt)
	item := udpGROItem{
		key:              key,
		bufsIndex:        uint16(bufsIndex),
		gsoSize:          uint16(len(pkt[udphOffset+header.UDPMinimumSize:])),
		iphLen:           uint8(udphOffset),
		cSumKnownInvalid: cSumKnownInvalid,
	}
	items, ok := u.itemsByFlow[key]
	if !ok {
		items = u.newItems()
	}
	items = append(items, item)
	u.itemsByFlow[key] = items
}

func (u *udpGROTable) updateAt(item udpGROItem, i int) {
	items := u.itemsByFlow[item.key]
	items[i] = item
}

// udpGROItem represents bookkeeping data for a UDP packet during the lifetime
// of a GRO evaluation across a vector of packets.
type udpGROItem struct {
	key              udpFlowKey
	bufsIndex        uint16 // the index into the original bufs slice
	numMerged        uint16 // the number of packets merged into this item
	gsoSize          uint16 // payload size
	iphLen           uint8  // ip header len
	cSumKnownInvalid bool   // UDP header checksum validity; a false value DOES NOT imply valid, just unknown.
}

func (u *udpGROTable) newItems() []udpGROItem {
	var items []udpGROItem
	items, u.itemsPool = u.itemsPool[len(u.itemsPool)-1], u.itemsPool[:len(u.itemsPool)-1]
	return items
}

func (u *udpGROTable) reset() {
	for k, items := range u.itemsByFlow {
		items = items[:0]
		u.itemsPool = append(u.itemsPool, items)
		delete(u.itemsByFlow, k)
	}
}

// canCoalesce represents the outcome of checking if two TCP packets are
// candidates for coalescing.
type canCoalesce int

const (
	coalescePrepend     canCoalesce = -1
	coalesceUnavailable canCoalesce = 0
	coalesceAppend      canCoalesce = 1
)

func ipHeadersCanCoalesce(pktA, pktB []byte) bool {
	if len(pktA) == 0 || len(pktB) == 0 {
		return false
	}

	ipVersion := pktA[0] >> 4
	if ipVersion != pktB[0]>>4 {
		// cannot coalesce with unequal IP versions
		return false
	}

	if ipVersion == header.IPv4Version {
		if len(pktA) < header.IPv4MinimumSize || len(pktB) < header.IPv4MinimumSize {
			return false
		}

		ipHdrA := header.IPv4(pktA)
		ipHdrB := header.IPv4(pktB)

		// Do the addresses match?
		if ipHdrA.SourceAddress() != ipHdrB.SourceAddress() || ipHdrA.DestinationAddress() != ipHdrB.DestinationAddress() {
			return false
		}

		typeOfServiceA, _ := ipHdrA.TOS()
		typeOfServiceB, _ := ipHdrB.TOS()

		// Type of service and TTL must match.
		if typeOfServiceA != typeOfServiceB || ipHdrA.TTL() != ipHdrB.TTL() {
			return false
		}

		// Make sure the flags match.
		if ipHdrA.Flags()&header.IPv4FlagDontFragment != ipHdrB.Flags()&header.IPv4FlagDontFragment {
			return false
		}
	} else {
		if len(pktA) < header.IPv6MinimumSize || len(pktB) < header.IPv6MinimumSize {
			return false
		}

		ipHdrA := header.IPv6(pktA)
		ipHdrB := header.IPv6(pktB)

		// Do the addresses match?
		if ipHdrA.SourceAddress() != ipHdrB.SourceAddress() || ipHdrA.DestinationAddress() != ipHdrB.DestinationAddress() {
			return false
		}

		trafficClassA, flowLabelA := ipHdrA.TOS()
		trafficClassB, flowLabelB := ipHdrB.TOS()

		// Traffic class, flow label, and hop limit must match.
		if trafficClassA != trafficClassB || flowLabelA != flowLabelB || ipHdrA.HopLimit() != ipHdrB.HopLimit() {
			return false
		}
	}

	return true
}

// udpPacketsCanCoalesce evaluates if pkt can be coalesced with the packet
// described by item. iphLen and gsoSize describe pkt. bufs is the vector of
// packets involved in the current GRO evaluation. bufsOffset is the offset at
// which packet data begins within bufs.
func udpPacketsCanCoalesce(pkt []byte, iphLen uint8, gsoSize uint16, item udpGROItem, packets []*network.Packet) canCoalesce {
	pktTarget := packets[item.bufsIndex].Bytes()
	if !ipHeadersCanCoalesce(pkt, pktTarget) {
		return coalesceUnavailable
	}
	if len(pktTarget[iphLen+header.UDPMinimumSize:])%int(item.gsoSize) != 0 {
		// A smaller than gsoSize packet has been appended previously.
		// Nothing can come after a smaller packet on the end.
		return coalesceUnavailable
	}
	if gsoSize > item.gsoSize {
		// We cannot have a larger packet following a smaller one.
		return coalesceUnavailable
	}
	return coalesceAppend
}

// tcpPacketsCanCoalesce evaluates if pkt can be coalesced with the packet
// described by item. This function makes considerations that match the kernel's
// GRO self tests, which can be found in tools/testing/selftests/net/gro.c.
func tcpPacketsCanCoalesce(pkt []byte, iphLen, tcphLen uint8, seq uint32, pshSet bool, gsoSize uint16, item tcpGROItem, packets []*network.Packet) canCoalesce {
	pktTarget := packets[item.bufsIndex].Bytes()
	if tcphLen != item.tcphLen {
		// cannot coalesce with unequal tcp options len
		return coalesceUnavailable
	}
	if tcphLen > 20 {
		if !bytes.Equal(pkt[iphLen+20:iphLen+tcphLen], pktTarget[item.iphLen+20:iphLen+tcphLen]) {
			// cannot coalesce with unequal tcp options
			return coalesceUnavailable
		}
	}
	if !ipHeadersCanCoalesce(pkt, pktTarget) {
		return coalesceUnavailable
	}
	// seq adjacency
	lhsLen := item.gsoSize
	lhsLen += item.numMerged * item.gsoSize
	if seq == item.sentSeq+uint32(lhsLen) { // pkt aligns following item from a seq num perspective
		if item.pshSet {
			// We cannot append to a segment that has the PSH flag set, PSH
			// can only be set on the final segment in a reassembled group.
			return coalesceUnavailable
		}
		if len(pktTarget[iphLen+tcphLen:])%int(item.gsoSize) != 0 {
			// A smaller than gsoSize packet has been appended previously.
			// Nothing can come after a smaller packet on the end.
			return coalesceUnavailable
		}
		if gsoSize > item.gsoSize {
			// We cannot have a larger packet following a smaller one.
			return coalesceUnavailable
		}
		return coalesceAppend
	} else if seq+uint32(gsoSize) == item.sentSeq { // pkt aligns in front of item from a seq num perspective
		if pshSet {
			// We cannot prepend with a segment that has the PSH flag set, PSH
			// can only be set on the final segment in a reassembled group.
			return coalesceUnavailable
		}
		if gsoSize < item.gsoSize {
			// We cannot have a larger packet following a smaller one.
			return coalesceUnavailable
		}
		if gsoSize > item.gsoSize && item.numMerged > 0 {
			// There's at least one previous merge, and we're larger than all
			// previous. This would put multiple smaller packets on the end.
			return coalesceUnavailable
		}
		return coalescePrepend
	}
	return coalesceUnavailable
}

func checksumValid(pkt []byte, iphLen uint8) bool {
	return ^checksum.Checksum(pkt[iphLen:], pseudoHeaderChecksum(pkt)) == 0
}

// coalesceResult represents the result of attempting to coalesce two TCP
// packets.
type coalesceResult int

const (
	coalesceInsufficientCap coalesceResult = iota
	coalescePSHEnding
	coalesceItemInvalidCSum
	coalescePktInvalidCSum
	coalesceSuccess
)

// coalesceUDPPackets attempts to coalesce pkt with the packet described by
// item, and returns the outcome.
func coalesceUDPPackets(pkt []byte, item *udpGROItem, packets []*network.Packet, isV6 bool) coalesceResult {
	bufsOffset := packets[item.bufsIndex].Offset
	pktHead := packets[item.bufsIndex].Bytes() // the packet that will end up at the front
	headersLen := item.iphLen + header.UDPMinimumSize
	coalescedLen := packets[item.bufsIndex].Size + len(pkt) - int(headersLen)

	if bufsOffset+coalescedLen > network.MaxPacketSize {
		// We don't want to allocate a new underlying array if capacity is
		// too small.
		return coalesceInsufficientCap
	}
	if item.numMerged == 0 {
		if item.cSumKnownInvalid || !checksumValid(packets[item.bufsIndex].Bytes(), item.iphLen) {
			return coalesceItemInvalidCSum
		}
	}
	if !checksumValid(pkt, item.iphLen) {
		return coalescePktInvalidCSum
	}
	packets[item.bufsIndex].Size += copy(
		packets[item.bufsIndex].Buf[bufsOffset+len(pktHead):], pkt[headersLen:])
	item.numMerged++
	return coalesceSuccess
}

// coalesceTCPPackets attempts to coalesce pkt with the packet described by
// item, and returns the outcome. This function may swap bufs elements in the
// event of a prepend as item's bufs index is already being tracked for writing
// to a Device.
func coalesceTCPPackets(mode canCoalesce, pkt []byte, pktBuffsIndex int, gsoSize uint16, seq uint32, pshSet bool, item *tcpGROItem, packets []*network.Packet, isV6 bool) coalesceResult {
	headersLen := item.iphLen + item.tcphLen
	bufsOffset := packets[item.bufsIndex].Offset
	coalescedLen := packets[item.bufsIndex].Size + len(pkt) - int(headersLen)

	// Copy data
	if mode == coalescePrepend {
		if bufsOffset+coalescedLen > network.MaxPacketSize {
			// We don't want to allocate a new underlying array if capacity is
			// too small.
			return coalesceInsufficientCap
		}
		if pshSet {
			return coalescePSHEnding
		}
		if item.numMerged == 0 {
			if !checksumValid(packets[item.bufsIndex].Bytes(), item.iphLen) {
				return coalesceItemInvalidCSum
			}
		}
		if !checksumValid(pkt, item.iphLen) {
			return coalescePktInvalidCSum
		}
		item.sentSeq = seq
		packets[pktBuffsIndex].Size += copy(packets[pktBuffsIndex].Buf[packets[pktBuffsIndex].Offset+len(pkt):],
			packets[item.bufsIndex].Bytes()[int(headersLen):])

		// Flip the slice headers in bufs as part of prepend. The index of item
		// is already being tracked for writing.
		packets[item.bufsIndex], packets[pktBuffsIndex] = packets[pktBuffsIndex], packets[item.bufsIndex]
	} else {
		pktHead := packets[item.bufsIndex].Bytes()
		if cap(pktHead)-bufsOffset < coalescedLen {
			// We don't want to allocate a new underlying array if capacity is
			// too small.
			return coalesceInsufficientCap
		}
		if item.numMerged == 0 {
			if !checksumValid(packets[item.bufsIndex].Bytes(), item.iphLen) {
				return coalesceItemInvalidCSum
			}
		}
		if !checksumValid(pkt, item.iphLen) {
			return coalescePktInvalidCSum
		}
		if pshSet {
			// We are appending a segment with PSH set.
			item.pshSet = pshSet
			pktHead[item.iphLen+header.TCPFlagsOffset] |= uint8(header.TCPFlagPsh)
		}
		packets[item.bufsIndex].Size += copy(
			packets[item.bufsIndex].Buf[bufsOffset+len(pktHead):], pkt[headersLen:])
	}

	if gsoSize > item.gsoSize {
		item.gsoSize = gsoSize
	}

	item.numMerged++
	return coalesceSuccess
}

const (
	ipv4SrcAddrOffset = 12
	ipv6SrcAddrOffset = 8
	maxUint16         = 1<<16 - 1
)

type groResult int

const (
	groResultNoop groResult = iota
	groResultTableInsert
	groResultCoalesced
)

// tcpGRO evaluates the TCP packet at pktI in bufs for coalescing with
// existing packets tracked in table. It returns a groResultNoop when no
// action was taken, groResultTableInsert when the evaluated packet was
// inserted into table, and groResultCoalesced when the evaluated packet was
// coalesced with another packet in table.
func tcpGRO(packets []*network.Packet, pktI int, table *tcpGROTable, isV6 bool) groResult {
	pkt := packets[pktI].Bytes()
	iphLen := int((pkt[0] & 0x0F) * 4)
	if isV6 {
		iphLen = 40
		ipv6HPayloadLen := int(binary.BigEndian.Uint16(pkt[4:]))
		if ipv6HPayloadLen != packets[pktI].Size-iphLen {
			return groResultNoop
		}
	} else {
		totalLen := int(binary.BigEndian.Uint16(pkt[2:]))
		if totalLen != packets[pktI].Size {
			return groResultNoop
		}
	}
	if packets[pktI].Size < iphLen {
		return groResultNoop
	}
	tcphLen := int((pkt[iphLen+12] >> 4) * 4)
	if tcphLen < 20 || tcphLen > 60 {
		return groResultNoop
	}
	if packets[pktI].Size < iphLen+tcphLen {
		return groResultNoop
	}
	if !isV6 {
		ipHdr := header.IPv4(pkt)
		if ipHdr.Flags()&header.IPv4FlagMoreFragments != 0 || ipHdr.FragmentOffset() != 0 {
			// no GRO support for fragmented segments for now
			return groResultNoop
		}
	}
	tcpFlags := pkt[iphLen+header.TCPFlagsOffset]
	var pshSet bool
	// not a candidate if any non-ACK flags (except PSH+ACK) are set
	if tcpFlags != uint8(header.TCPFlagAck) {
		if pkt[iphLen+header.TCPFlagsOffset] != uint8(header.TCPFlagAck|header.TCPFlagPsh) {
			return groResultNoop
		}
		pshSet = true
	}
	gsoSize := uint16(packets[pktI].Size - tcphLen - iphLen)
	// not a candidate if payload len is 0
	if gsoSize < 1 {
		return groResultNoop
	}
	seq := binary.BigEndian.Uint32(pkt[iphLen+4:])
	items, existing := table.lookupOrInsert(pkt, iphLen, tcphLen, pktI)
	if !existing {
		return groResultTableInsert
	}
	for i := len(items) - 1; i >= 0; i-- {
		// In the best case of packets arriving in order iterating in reverse is
		// more efficient if there are multiple items for a given flow. This
		// also enables a natural table.deleteAt() in the
		// coalesceItemInvalidCSum case without the need for index tracking.
		// This algorithm makes a best effort to coalesce in the event of
		// unordered packets, where pkt may land anywhere in items from a
		// sequence number perspective, however once an item is inserted into
		// the table it is never compared across other items later.
		item := items[i]
		can := tcpPacketsCanCoalesce(pkt, uint8(iphLen), uint8(tcphLen), seq, pshSet, gsoSize, item, packets)
		if can != coalesceUnavailable {
			result := coalesceTCPPackets(can, pkt, pktI, gsoSize, seq, pshSet, &item, packets, isV6)
			switch result {
			case coalesceSuccess:
				table.updateAt(item, i)
				return groResultCoalesced
			case coalesceItemInvalidCSum:
				// delete the item with an invalid csum
				table.deleteAt(item.key, i)

				// Prepend an empty virtioNetHdr as we won't visit this item again.
				var hdr virtioNetHdr
				if err := hdr.encode(packets[item.bufsIndex].Buf[packets[item.bufsIndex].Offset-VirtioNetHdrLen:]); err != nil {
					return groResultNoop
				}
				packets[item.bufsIndex].Offset -= VirtioNetHdrLen
				packets[item.bufsIndex].Size += VirtioNetHdrLen
			case coalescePktInvalidCSum:
				// no point in inserting an item that we can't coalesce
				return groResultNoop
			default:
			}
		}
	}
	// failed to coalesce with any other packets; store the item in the flow
	table.insert(pkt, iphLen, tcphLen, pktI)
	return groResultTableInsert
}

// applyTCPCoalesceAccounting updates bufs to account for coalescing based on the
// metadata found in table.
func applyTCPCoalesceAccounting(packets []*network.Packet, table *tcpGROTable) error {
	for _, items := range table.itemsByFlow {
		for _, item := range items {
			if item.numMerged > 0 {
				hdr := virtioNetHdr{
					flags:      unix.VIRTIO_NET_HDR_F_NEEDS_CSUM, // this turns into CHECKSUM_PARTIAL in the skb
					hdrLen:     uint16(item.iphLen + item.tcphLen),
					gsoSize:    item.gsoSize,
					csumStart:  uint16(item.iphLen),
					csumOffset: 16,
				}
				pkt := packets[item.bufsIndex].Bytes()

				// Recalculate the total len (IPv4) or payload len (IPv6).
				// Recalculate the (IPv4) header checksum.
				if item.key.isV6 {
					hdr.gsoType = unix.VIRTIO_NET_HDR_GSO_TCPV6
					binary.BigEndian.PutUint16(pkt[4:], uint16(len(pkt))-uint16(item.iphLen)) // set new IPv6 header payload len
				} else {
					hdr.gsoType = unix.VIRTIO_NET_HDR_GSO_TCPV4
					pkt[10], pkt[11] = 0, 0
					binary.BigEndian.PutUint16(pkt[2:], uint16(len(pkt))) // set new total length
					iphCSum := ^checksum.Checksum(pkt[:item.iphLen], 0)   // compute IPv4 header checksum
					binary.BigEndian.PutUint16(pkt[10:], iphCSum)         // set IPv4 header checksum field
				}
				if err := hdr.encode(packets[item.bufsIndex].Buf[packets[item.bufsIndex].Offset-VirtioNetHdrLen:]); err != nil {
					return err
				}
				packets[item.bufsIndex].Offset -= VirtioNetHdrLen
				packets[item.bufsIndex].Size += VirtioNetHdrLen

				// Calculate the pseudo header checksum and place it at the TCP
				// checksum offset. Downstream checksum offloading will combine
				// this with computation of the tcp header and payload checksum.
				binary.BigEndian.PutUint16(pkt[hdr.csumStart+hdr.csumOffset:],
					checksum.Checksum([]byte{}, pseudoHeaderChecksum(pkt)))
			} else {
				var hdr virtioNetHdr
				if err := hdr.encode(packets[item.bufsIndex].Buf[packets[item.bufsIndex].Offset-VirtioNetHdrLen:]); err != nil {
					return err
				}
				packets[item.bufsIndex].Offset -= VirtioNetHdrLen
				packets[item.bufsIndex].Size += VirtioNetHdrLen
			}
		}
	}
	return nil
}

// applyUDPCoalesceAccounting updates bufs to account for coalescing based on the
// metadata found in table.
func applyUDPCoalesceAccounting(packets []*network.Packet, table *udpGROTable) error {
	for _, items := range table.itemsByFlow {
		for _, item := range items {
			if item.numMerged > 0 {
				hdr := virtioNetHdr{
					flags:      unix.VIRTIO_NET_HDR_F_NEEDS_CSUM, // this turns into CHECKSUM_PARTIAL in the skb
					hdrLen:     uint16(item.iphLen + header.UDPMinimumSize),
					gsoSize:    item.gsoSize,
					csumStart:  uint16(item.iphLen),
					csumOffset: 6,
				}
				pkt := packets[item.bufsIndex].Bytes()

				// Recalculate the total len (IPv4) or payload len (IPv6).
				// Recalculate the (IPv4) header checksum.
				hdr.gsoType = unix.VIRTIO_NET_HDR_GSO_UDP_L4
				if item.key.isV6 {
					binary.BigEndian.PutUint16(pkt[4:], uint16(len(pkt))-uint16(item.iphLen)) // set new IPv6 header payload len
				} else {
					pkt[10], pkt[11] = 0, 0
					binary.BigEndian.PutUint16(pkt[2:], uint16(len(pkt))) // set new total length
					iphCSum := ^checksum.Checksum(pkt[:item.iphLen], 0)   // compute IPv4 header checksum
					binary.BigEndian.PutUint16(pkt[10:], iphCSum)         // set IPv4 header checksum field
				}
				if err := hdr.encode(packets[item.bufsIndex].Buf[packets[item.bufsIndex].Offset-VirtioNetHdrLen:]); err != nil {
					return err
				}
				packets[item.bufsIndex].Offset -= VirtioNetHdrLen
				packets[item.bufsIndex].Size += VirtioNetHdrLen

				// Recalculate the UDP len field value
				binary.BigEndian.PutUint16(pkt[item.iphLen+4:], uint16(len(pkt[item.iphLen:])))

				// Calculate the pseudo header checksum and place it at the UDP
				// checksum offset. Downstream checksum offloading will combine
				// this with computation of the udp header and payload checksum.
				binary.BigEndian.PutUint16(pkt[hdr.csumStart+hdr.csumOffset:],
					checksum.Checksum([]byte{}, pseudoHeaderChecksum(pkt)))
			} else {
				var hdr virtioNetHdr
				if err := hdr.encode(packets[item.bufsIndex].Buf[packets[item.bufsIndex].Offset-VirtioNetHdrLen:]); err != nil {
					return err
				}
				packets[item.bufsIndex].Offset -= VirtioNetHdrLen
				packets[item.bufsIndex].Size += VirtioNetHdrLen
			}
		}
	}
	return nil
}

type groCandidateType uint8

const (
	notGROCandidate groCandidateType = iota
	tcp4GROCandidate
	tcp6GROCandidate
	udp4GROCandidate
	udp6GROCandidate
)

func packetIsGROCandidate(b []byte, canUDPGRO bool) groCandidateType {
	if len(b) < 28 {
		return notGROCandidate
	}
	if b[0]>>4 == 4 {
		if b[0]&0x0F != 5 {
			// IPv4 packets w/IP options do not coalesce
			return notGROCandidate
		}
		if b[9] == unix.IPPROTO_TCP && len(b) >= 40 {
			return tcp4GROCandidate
		}
		if b[9] == unix.IPPROTO_UDP && canUDPGRO {
			return udp4GROCandidate
		}
	} else if b[0]>>4 == 6 {
		if b[6] == unix.IPPROTO_TCP && len(b) >= 60 {
			return tcp6GROCandidate
		}
		if b[6] == unix.IPPROTO_UDP && len(b) >= 48 && canUDPGRO {
			return udp6GROCandidate
		}
	}
	return notGROCandidate
}

// udpGRO evaluates the UDP packet at pktI in bufs for coalescing with
// existing packets tracked in table. It returns a groResultNoop when no
// action was taken, groResultTableInsert when the evaluated packet was
// inserted into table, and groResultCoalesced when the evaluated packet was
// coalesced with another packet in table.
func udpGRO(packets []*network.Packet, pktI int, table *udpGROTable, isV6 bool) groResult {
	pkt := packets[pktI].Bytes()
	iphLen := int((pkt[0] & 0x0F) * 4)
	if isV6 {
		iphLen = 40
		ipv6HPayloadLen := int(binary.BigEndian.Uint16(pkt[4:]))
		if ipv6HPayloadLen != len(pkt)-iphLen {
			return groResultNoop
		}
	} else {
		totalLen := int(binary.BigEndian.Uint16(pkt[2:]))
		if totalLen != len(pkt) {
			return groResultNoop
		}
	}
	if len(pkt) < iphLen {
		return groResultNoop
	}
	if len(pkt) < iphLen+header.UDPMinimumSize {
		return groResultNoop
	}
	if !isV6 {
		ipHdr := header.IPv4(pkt)
		if ipHdr.Flags()&header.IPv4FlagMoreFragments != 0 || ipHdr.FragmentOffset() != 0 {
			// no GRO support for fragmented segments for now
			return groResultNoop
		}
	}
	gsoSize := uint16(len(pkt) - header.UDPMinimumSize - iphLen)
	// not a candidate if payload len is 0
	if gsoSize < 1 {
		return groResultNoop
	}
	items, existing := table.lookupOrInsert(pkt, iphLen, pktI)
	if !existing {
		return groResultTableInsert
	}
	// With UDP we only check the last item, otherwise we could reorder packets
	// for a given flow. We must also always insert a new item, or successfully
	// coalesce with an existing item, for the same reason.
	item := items[len(items)-1]
	can := udpPacketsCanCoalesce(pkt, uint8(iphLen), gsoSize, item, packets)
	var pktCSumKnownInvalid bool
	if can == coalesceAppend {
		result := coalesceUDPPackets(pkt, &item, packets, isV6)
		switch result {
		case coalesceSuccess:
			table.updateAt(item, len(items)-1)
			return groResultCoalesced
		case coalesceItemInvalidCSum:
			// If the existing item has an invalid csum we take no action. A new
			// item will be stored after it, and the existing item will never be
			// revisited as part of future coalescing candidacy checks.
		case coalescePktInvalidCSum:
			// We must insert a new item, but we also mark it as invalid csum
			// to prevent a repeat checksum validation.
			pktCSumKnownInvalid = true
		default:
		}
	}
	// failed to coalesce with any other packets; store the item in the flow
	table.insert(pkt, iphLen, pktI, pktCSumKnownInvalid)
	return groResultTableInsert
}

// handleGRO evaluates bufs for GRO, and writes the indices of the resulting
// packets into toWrite. toWrite, tcpTable, and udpTable should initially be
// empty (but non-nil), and are passed in to save allocs as the caller may reset
// and recycle them across vectors of packets. canUDPGRO indicates if UDP GRO is
// supported.
func (nic *Interface) handleGRO(packets []*network.Packet, toWrite []int) ([]int, error) {
	for i, pkt := range packets {
		if pkt.Offset < VirtioNetHdrLen {
			return toWrite, errors.New("invalid offset, please provide packets with an offset >= tun.VirtioNetHdrLen")
		}
		var result groResult
		switch packetIsGROCandidate(pkt.Bytes(), nic.udpGSO) {
		case tcp4GROCandidate:
			result = tcpGRO(packets, i, nic.tcpGROTable, false)
		case tcp6GROCandidate:
			result = tcpGRO(packets, i, nic.tcpGROTable, true)
		case udp4GROCandidate:
			result = udpGRO(packets, i, nic.udpGROTable, false)
		case udp6GROCandidate:
			result = udpGRO(packets, i, nic.udpGROTable, true)
		}
		switch result {
		case groResultNoop:
			var hdr virtioNetHdr
			if err := hdr.encode(pkt.Buf[pkt.Offset-VirtioNetHdrLen:]); err != nil {
				return toWrite, err
			}
			pkt.Offset -= VirtioNetHdrLen
			pkt.Size += VirtioNetHdrLen
			fallthrough
		case groResultTableInsert:
			toWrite = append(toWrite, i)
		}
	}
	errTCP := applyTCPCoalesceAccounting(packets, nic.tcpGROTable)
	errUDP := applyUDPCoalesceAccounting(packets, nic.udpGROTable)
	return toWrite, errors.Join(errTCP, errUDP)
}

func pseudoHeaderChecksum(pkt []byte) uint16 {
	ipVersion := pkt[0] >> 4
	if ipVersion == header.IPv4Version {
		ipHdr := header.IPv4(pkt)

		return header.PseudoHeaderChecksum(
			tcpip.TransportProtocolNumber(ipHdr.Protocol()),
			ipHdr.SourceAddress(),
			ipHdr.DestinationAddress(),
			uint16(len(pkt)-int(ipHdr.HeaderLength())))
	} else {
		ipHdr := header.IPv6(pkt)

		return header.PseudoHeaderChecksum(
			ipHdr.TransportProtocol(),
			ipHdr.SourceAddress(),
			ipHdr.DestinationAddress(),
			uint16(len(pkt)-header.IPv6MinimumSize))
	}
}
