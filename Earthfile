VERSION 0.7
FROM golang:1.22-bookworm
WORKDIR /workspace

tidy:
  LOCALLY
  RUN go mod tidy
  RUN go fmt ./...

lint:
  FROM golangci/golangci-lint:v1.57.2
  WORKDIR /workspace
  COPY . .
  RUN golangci-lint run --timeout 5m ./...

test:
  COPY go.mod go.sum .
  RUN go mod download
  COPY . .
  RUN go test -coverprofile=coverage.out -v ./...
  SAVE ARTIFACT coverage.out AS LOCAL coverage.out

examples:
  COPY go.mod go.sum .
  RUN go mod download
  COPY . .
  RUN mkdir /workspace/dist
  WORKDIR /workspace/examples
  RUN for example in $(find . -name 'main.go'); do \
      (cd "${example%/main.go}" && go build -o "/workspace/dist/${example%/main.go}" .); \
    done
  SAVE ARTIFACT /workspace/dist AS LOCAL dist