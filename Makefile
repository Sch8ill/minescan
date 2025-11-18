bin_name=minescan
target=./cmd

all: build

run:
	go run $(target)

build:
	CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -o build/$(bin_name) $(target)

clean:
	rm -rf build