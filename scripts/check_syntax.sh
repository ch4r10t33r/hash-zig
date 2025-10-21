#!/bin/sh
set -e
for f in $(find . -name "*.zig"); do
    echo "Checking syntax: $f"
    zig ast-check "$f"
done
