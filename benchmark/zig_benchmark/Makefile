ZIG?=zig
URL:=git+https://github.com/ch4r10t33r/hash-zig#master

.PHONY: fetch build run clean

fetch:
	$(ZIG) fetch --save $(URL)

build: fetch
	$(ZIG) build -Doptimize=ReleaseFast

run: build
	./zig-out/bin/keygen_bench

clean:
	rm -rf zig-out .zig-cache

