.DEFAULT_GOAL = build

protobuf: proto/protocol.proto
	protoc --go_out="./internal/" proto/protocol.proto

build: protobuf
	@mkdir -p build
	go build -o build/netdog main.go
