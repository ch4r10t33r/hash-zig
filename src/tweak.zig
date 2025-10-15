//! Tweak types for Poseidon hash functions
//! Matches Rust's PoseidonTweak implementation from hash-sig
//!
//! Tweaks provide domain separation for different uses of the hash function:
//! - TreeTweak: For Merkle tree node hashing
//! - ChainTweak: For Winternitz hash chains

const std = @import("std");
const field = @import("field.zig");
const FieldElement = field.FieldElement;

/// Tweak type for Poseidon hash functions
/// Provides domain separation between tree hashing and chain hashing
pub const PoseidonTweak = union(enum) {
    tree_tweak: TreeTweak,
    chain_tweak: ChainTweak,

    /// Tweak for Merkle tree node hashing
    pub const TreeTweak = struct {
        level: u8, // Level in the tree (0 = leaves, height = root)
        pos_in_level: u32, // Position within the level
    };

    /// Tweak for Winternitz hash chain iteration
    pub const ChainTweak = struct {
        epoch: u32, // Which signature (leaf index)
        chain_index: u8, // Which chain (0..21 for w=8)
        pos_in_chain: u8, // Position in the chain (1..255 for w=8)
    };

    /// Convert tweak to field elements
    /// Matches Rust's to_field_elements() implementation
    ///
    /// The tweak is encoded as a large integer with different layout for each type,
    /// then split into field elements using base-p representation.
    pub fn toFieldElements(
        self: PoseidonTweak,
        comptime tweak_len: usize,
    ) [tweak_len]FieldElement {
        // Encode tweak as a 128-bit integer with specific bit layout
        const acc: u128 = switch (self) {
            .tree_tweak => |t| blk: {
                // Layout: [level (bits 40-47)] [pos_in_level (bits 8-39)] [separator (bits 0-7)]
                const sep = @as(u128, field.TWEAK_SEPARATOR_FOR_TREE_HASH);
                const pos = @as(u128, t.pos_in_level);
                const lvl = @as(u128, t.level);
                break :blk (lvl << 40) | (pos << 8) | sep;
            },
            .chain_tweak => |c| blk: {
                // Layout: [epoch (bits 24-55)] [chain_idx (bits 16-23)] [pos (bits 8-15)] [separator (bits 0-7)]
                const sep = @as(u128, field.TWEAK_SEPARATOR_FOR_CHAIN_HASH);
                const pos = @as(u128, c.pos_in_chain);
                const chain = @as(u128, c.chain_index);
                const ep = @as(u128, c.epoch);
                break :blk (ep << 24) | (chain << 16) | (pos << 8) | sep;
            },
        };

        // Split the integer into field elements using base-p representation
        // This matches Rust's implementation: digit = acc % p, then acc /= p
        var result: [tweak_len]FieldElement = undefined;
        var remaining = acc;

        for (&result) |*fe| {
            const digit = remaining % FieldElement.PRIME;
            fe.* = FieldElement.fromU64(@intCast(digit));
            remaining /= FieldElement.PRIME;
        }

        return result;
    }

    /// Create a tree tweak for hashing a parent node
    pub fn forTree(level: u8, pos_in_level: u32) PoseidonTweak {
        return .{ .tree_tweak = .{ .level = level, .pos_in_level = pos_in_level } };
    }

    /// Create a chain tweak for Winternitz hash chain iteration
    pub fn forChain(epoch: u32, chain_index: u8, pos_in_chain: u8) PoseidonTweak {
        return .{ .chain_tweak = .{ .epoch = epoch, .chain_index = chain_index, .pos_in_chain = pos_in_chain } };
    }
};

// ============================================================================
// Tests
// ============================================================================

test "tweak: tree tweak creation" {
    const tweak = PoseidonTweak.forTree(5, 123);

    switch (tweak) {
        .tree_tweak => |t| {
            try std.testing.expectEqual(@as(u8, 5), t.level);
            try std.testing.expectEqual(@as(u32, 123), t.pos_in_level);
        },
        else => return error.WrongTweakType,
    }
}

test "tweak: chain tweak creation" {
    const tweak = PoseidonTweak.forChain(10, 3, 42);

    switch (tweak) {
        .chain_tweak => |c| {
            try std.testing.expectEqual(@as(u32, 10), c.epoch);
            try std.testing.expectEqual(@as(u8, 3), c.chain_index);
            try std.testing.expectEqual(@as(u8, 42), c.pos_in_chain);
        },
        else => return error.WrongTweakType,
    }
}

test "tweak: tree tweak to field elements" {
    const tweak = PoseidonTweak.forTree(0, 0);
    const fes = tweak.toFieldElements(2);

    // For tree tweak with level=0, pos=0, separator=0x00:
    // acc = (0 << 40) | (0 << 8) | 0x00 = 0
    // fe[0] = 0 % p = 0
    // fe[1] = 0 / p = 0
    try std.testing.expect(fes[0].isZero());
    try std.testing.expect(fes[1].isZero());
}

test "tweak: chain tweak to field elements" {
    const tweak = PoseidonTweak.forChain(0, 0, 0);
    const fes = tweak.toFieldElements(2);

    // For chain tweak with epoch=0, chain=0, pos=0, separator=0x01:
    // acc = (0 << 24) | (0 << 16) | (0 << 8) | 0x01 = 1
    // fe[0] = 1 % p = 1
    // fe[1] = 1 / p = 0 (since p > 1)
    try std.testing.expect(fes[0].isOne());
    try std.testing.expect(fes[1].isZero());
}

test "tweak: different separators" {
    const tree_tweak = PoseidonTweak.forTree(0, 0);
    const chain_tweak = PoseidonTweak.forChain(0, 0, 0);

    const tree_fes = tree_tweak.toFieldElements(2);
    const chain_fes = chain_tweak.toFieldElements(2);

    // They should produce different field elements due to different separators
    try std.testing.expect(!tree_fes[0].eql(chain_fes[0]));
}

test "tweak: tree tweak with actual values" {
    const tweak = PoseidonTweak.forTree(5, 100);
    const fes = tweak.toFieldElements(2);

    // acc = (5 << 40) | (100 << 8) | 0x00
    // = 5497558138880 + 25600 + 0 = 5497558164480
    const expected_acc: u128 = (5 << 40) | (100 << 8);

    // fe[0] = acc % PRIME
    const fe0_expected = FieldElement.fromU64(expected_acc % FieldElement.PRIME);
    try std.testing.expect(fes[0].eql(fe0_expected));

    // fe[1] = (acc / PRIME) % PRIME
    const fe1_expected = FieldElement.fromU64((expected_acc / FieldElement.PRIME) % FieldElement.PRIME);
    try std.testing.expect(fes[1].eql(fe1_expected));
}

test "tweak: chain tweak with actual values" {
    const tweak = PoseidonTweak.forChain(100, 5, 10);
    const fes = tweak.toFieldElements(2);

    // acc = (100 << 24) | (5 << 16) | (10 << 8) | 0x01
    // = 1677721600 + 327680 + 2560 + 1 = 1678051841
    const expected_acc: u128 = (@as(u128, 100) << 24) | (@as(u128, 5) << 16) | (@as(u128, 10) << 8) | 0x01;

    const fe0_expected = FieldElement.fromU64(expected_acc % FieldElement.PRIME);
    try std.testing.expect(fes[0].eql(fe0_expected));

    const fe1_expected = FieldElement.fromU64((expected_acc / FieldElement.PRIME) % FieldElement.PRIME);
    try std.testing.expect(fes[1].eql(fe1_expected));
}

test "tweak: deterministic" {
    const tweak1 = PoseidonTweak.forTree(3, 42);
    const tweak2 = PoseidonTweak.forTree(3, 42);

    const fes1 = tweak1.toFieldElements(2);
    const fes2 = tweak2.toFieldElements(2);

    // Same input should produce same field elements
    for (fes1, fes2) |fe1, fe2| {
        try std.testing.expect(fe1.eql(fe2));
    }
}

test "tweak: different levels produce different tweaks" {
    const tweak_level_0 = PoseidonTweak.forTree(0, 42);
    const tweak_level_1 = PoseidonTweak.forTree(1, 42);

    const fes0 = tweak_level_0.toFieldElements(2);
    const fes1 = tweak_level_1.toFieldElements(2);

    // Different levels should produce different field elements
    try std.testing.expect(!fes0[0].eql(fes1[0]) or !fes0[1].eql(fes1[1]));
}

test "tweak: different positions produce different tweaks" {
    const tweak_pos_0 = PoseidonTweak.forTree(5, 0);
    const tweak_pos_1 = PoseidonTweak.forTree(5, 1);

    const fes0 = tweak_pos_0.toFieldElements(2);
    const fes1 = tweak_pos_1.toFieldElements(2);

    // Different positions should produce different field elements
    try std.testing.expect(!fes0[0].eql(fes1[0]) or !fes0[1].eql(fes1[1]));
}
