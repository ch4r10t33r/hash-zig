# Hash-Zig Examples

This directory contains example programs demonstrating the usage of the hash-zig library for hash-based signatures.

## Available Examples

### 1. basic_usage.zig
**Byte-based implementation** (original version)

Basic usage demonstrating:
- Key generation
- Message signing
- Signature verification
- Performance timing

Run with:
```bash
zig build example
```

### 2. basic_usage_native.zig
**Field-native implementation** (Rust-compatible)

Demonstrates the field-native implementation using KoalaBear field elements, compatible with the Rust hash-sig library.

Features:
- Direct field element operations (no byte conversions)
- 8× memory reduction for tree nodes (4 bytes vs 32 bytes)
- ChaCha12 RNG matching Rust's `StdRng`
- Poseidon2 with KoalaBear field
- Compatible with Rust hash-sig architecture

Run with:
```bash
zig build example-native
```

**Performance (lifetime 2^10 = 1,024 signatures)**:
- Key Generation: ~29 seconds
- Signing: ~100 ms
- Verification: ~120 ms

---

## Comparison: Byte-Based vs Field-Native

| Feature | Byte-Based | Field-Native |
|---------|------------|--------------|
| **Public Key** | 52 bytes | 24 bytes |
| **Tree Node** | 32 bytes | 4 bytes |
| **Hash Operations** | Bytes | Field elements |
| **Rust Compatible** | ❌ No | ✅ Yes |
| **Memory Usage** | Higher | Lower (8×) |

---

## Configuration Options

Both examples use lifetime `2^10` (1,024 signatures) by default. You can modify the lifetime in the code:

```zig
// Available lifetimes:
const params = hash_zig.Parameters.init(.lifetime_2_10);  // 1,024 signatures
const params = hash_zig.Parameters.init(.lifetime_2_16);  // 65,536 signatures
const params = hash_zig.Parameters.init(.lifetime_2_20);  // 1,048,576 signatures
```

**Note**: Higher lifetimes require significantly more key generation time:
- `2^10`: ~29 seconds
- `2^16`: ~30 minutes (estimated)
- `2^20`: ~8 hours (estimated)

---

## Building Examples

### Build only (without running)
```bash
zig build install
```

### Build and run byte-based example
```bash
zig build example
```

### Build and run field-native example
```bash
zig build example-native
```

---

## Development

When adding new examples:
1. Create `your_example.zig` in this directory
2. Add it to `build.zig`:
   ```zig
   const your_example_module = b.createModule(.{
       .root_source_file = b.path("examples/your_example.zig"),
       .target = target,
       .optimize = optimize,
   });
   your_example_module.addImport("hash-zig", hash_zig_module);
   
   const your_example = b.addExecutable(.{
       .name = "your-example-name",
       .root_module = your_example_module,
   });
   b.installArtifact(your_example);
   
   const run_your_example = b.addRunArtifact(your_example);
   const your_example_step = b.step("your-example", "Run your example");
   your_example_step.dependOn(&run_your_example.step);
   ```
3. Update this README

---

## Next Steps

- Explore the field-native implementation for better performance and Rust compatibility
- Experiment with different lifetime configurations
- Compare performance between byte-based and field-native versions
- Test cross-implementation compatibility with Rust hash-sig

For more information, see the main project [README](../README.md).

