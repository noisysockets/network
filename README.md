# Network

Network is a Go package that provides a host independent abstraction for network 
operations. It is designed to be used as a drop-in replacement for the Go 
[net](https://pkg.go.dev/net) package, allowing it to be used with existing
networking code.

This is implemented using a userspace TCP/IP stack based on 
[Netstack](https://gvisor.dev/docs/user_guide/networking/) from the 
[gVisor](https://github.com/google/gvisor) project.

Part of the [Noisy Sockets](https://github.com/noisysockets/noisysockets) project.

## Usage

Example usage of the package can be found in the [examples](./examples) directory.