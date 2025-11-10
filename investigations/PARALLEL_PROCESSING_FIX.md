# Fix for Parallel Processing in Zig

## Problem

Zig currently processes tree building **sequentially** while Rust processes it **in parallel**. This causes different RNG consumption patterns and different final roots.

## Current Zig Implementation (Sequential)

```zig
for (0..parents_len) |i| {
    // Hash two children together (matching Rust exactly)
    const left_idx = i * 2;
    const right_idx = i * 2 + 1;
    
    const left = current_layer.nodes[left_idx];
    const right = current_layer.nodes[right_idx];
    
    // Process hash operation sequentially
    const hash_result = try self.applyPoseidonTreeTweakHashWithSeparateInputs(left_slice, right_slice, @as(u8, @intCast(current_level)), parent_pos, parameter);
    // ...
}
```

## Rust Implementation (Parallel)

```rust
let parents = prev
    .nodes
    .par_chunks_exact(2)
    .enumerate()
    .map(|(i, children)| {
        // Parent index in this layer
        let parent_pos = (parent_start + i) as u32;
        let tweak_level = (level as u8) + 1;
        // Hash children into their parent using the tweak
        let result = TH::apply(
            parameter,
            &TH::tree_tweak(tweak_level, parent_pos),
            children,
        );
        result
    })
    .collect();
```

## Solution

Zig needs to be modified to process all hash operations within a layer **in parallel** to match Rust's behavior. This requires:

1. **Parallel processing** of all pairs within each layer
2. **Consistent RNG consumption order** across all parallel operations
3. **Matching the exact sequence** of hash operations

## Implementation Strategy

1. **Use Zig's async/await** or **threading** to process multiple hash operations simultaneously
2. **Ensure RNG state consistency** across parallel operations
3. **Match Rust's exact processing order** for hash operations

## Critical Insight

The issue is not just about parallel vs sequential processing - it's about **RNG consumption order**. When operations happen in parallel, the RNG state is consumed in a different order than when they happen sequentially, leading to completely different intermediate values and final roots.

This explains why all foundational components match (parameters, PRF keys, hash functions, etc.) but the final roots are completely different - it's a fundamental difference in the **order of operations** during tree building.
