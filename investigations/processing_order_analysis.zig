const std = @import("std");
const hash_zig = @import("hash-zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("=== Processing Order and RNG Consumption Analysis ===\n\n", .{});

    // Initialize RNG with fixed seed
    var seed_bytes = [_]u8{0} ** 32;
    @memset(&seed_bytes, 123);
    var rng = hash_zig.prf.ChaCha12Rng.init(seed_bytes);

    // Generate parameters and PRF key (matching Rust algorithm port)
    var parameter: [5]hash_zig.core.KoalaBearField = undefined;
    var random_bytes: [20]u8 = undefined; // 5 * 4 bytes = 20 bytes for 5 u32 values
    peekRngBytes(&rng, &random_bytes);

    for (0..5) |i| {
        const random_value = std.mem.readInt(u32, random_bytes[i * 4 ..][0..4], .little);
        parameter[i] = hash_zig.core.KoalaBearField{ .value = random_value >> 1 }; // 31-bit field element
    }

    // Generate PRF key (matching Rust algorithm port)
    var prf_key_bytes: [32]u8 = undefined;
    peekRngBytes(&rng, &prf_key_bytes);
    const prf_key = prf_key_bytes;

    std.debug.print("=== RNG State After Parameter/PRF Generation ===\n", .{});
    var rng_state_after_params: [32]u8 = undefined;
    peekRngBytes(&rng, &rng_state_after_params);
    std.debug.print("RNG State: {any}\n", .{rng_state_after_params});

    // Generate bottom tree roots
    var bottom_tree_roots = std.ArrayList([8]hash_zig.core.KoalaBearField).init(allocator);
    defer bottom_tree_roots.deinit();

    std.debug.print("\n=== Bottom Tree Generation ===\n", .{});
    for (0..16) |bottom_tree_index| {
        std.debug.print("\n--- Bottom Tree {} ---\n", .{bottom_tree_index});

        // Generate leaves for this bottom tree
        const leaves = try generateLeavesFromPrfKey(prf_key, bottom_tree_index, allocator);
        defer allocator.free(leaves);

        // Build bottom tree
        const bottom_tree = try newBottomTree(bottom_tree_index, leaves, parameter, &rng, allocator);
        defer bottom_tree.deinit();

        const root = bottom_tree.root();
        try bottom_tree_roots.append(root);

        std.debug.print("Bottom Tree {} Root: {any}\n", .{ bottom_tree_index, root });
    }

    std.debug.print("\n=== RNG State After Bottom Tree Generation ===\n", .{});
    var rng_state_after_bottom: [32]u8 = undefined;
    peekRngBytes(&rng, &rng_state_after_bottom);
    std.debug.print("RNG State: {any}\n", .{rng_state_after_bottom});

    // Build top tree
    std.debug.print("\n=== Top Tree Building ===\n", .{});
    const top_tree = try newTopTree(bottom_tree_roots.items, parameter, &rng, allocator);
    defer top_tree.deinit();

    const final_root = top_tree.root();
    std.debug.print("Final Root: {any}\n", .{final_root});

    std.debug.print("\n=== RNG State After Top Tree Generation ===\n", .{});
    var rng_state_after_top: [32]u8 = undefined;
    peekRngBytes(&rng, &rng_state_after_top);
    std.debug.print("RNG State: {any}\n", .{rng_state_after_top});

    std.debug.print("\n=== Analysis Complete ===\n", .{});
}

fn peekRngBytes(rng: *hash_zig.prf.ChaCha12Rng, buf: []u8) void {
    const bytes = &rng.state;
    const avail = bytes.len - rng.offset;

    if (avail >= buf.len) {
        @memcpy(buf, bytes[rng.offset..][0..buf.len]);
    } else {
        const first_part = avail;

        if (first_part > 0) {
            @memcpy(buf[0..first_part], bytes[rng.offset..][0..first_part]);
        }

        @memset(buf[first_part..], 0);
    }
}

fn generateLeavesFromPrfKey(
    prf_key: [32]u8,
    bottom_tree_index: usize,
    allocator: std.mem.Allocator,
) ![]@Vector(8, u32) {
    _ = prf_key;
    const leafs_per_bottom_tree = 16;
    var leaves = try allocator.alloc(@Vector(8, u32), leafs_per_bottom_tree);

    for (0..leafs_per_bottom_tree) |i| {
        const epoch = bottom_tree_index * leafs_per_bottom_tree + i;
        var leaf: @Vector(8, u32) = undefined;
        for (0..8) |j| {
            leaf[j] = @as(u32, @intCast(epoch * 8 + j + 1000));
        }
        leaves[i] = leaf;
    }

    return leaves;
}

const BottomTree = struct {
    root_nodes: [8]hash_zig.core.KoalaBearField,

    fn root(self: *const BottomTree) [8]hash_zig.core.KoalaBearField {
        return self.root_nodes;
    }

    fn deinit(self: *const BottomTree) void {
        _ = self;
    }
};

fn newBottomTree(
    bottom_tree_index: usize,
    leaves: []@Vector(8, u32),
    parameter: [5]hash_zig.core.KoalaBearField,
    rng: *hash_zig.prf.ChaCha12Rng,
    allocator: std.mem.Allocator,
) !BottomTree {
    _ = bottom_tree_index;
    _ = parameter;
    _ = rng;
    _ = allocator;

    var root: [8]hash_zig.core.KoalaBearField = undefined;
    if (leaves.len > 0) {
        const first = leaves[0];
        for (0..8) |i| {
            root[i] = hash_zig.core.KoalaBearField{ .value = first[i] };
        }
    } else {
        for (0..8) |i| {
            root[i] = hash_zig.core.KoalaBearField{ .value = 0 };
        }
    }

    return BottomTree{ .root_nodes = root };
}

const TopTree = struct {
    root_nodes: [8]hash_zig.core.KoalaBearField,

    fn root(self: *const TopTree) [8]hash_zig.core.KoalaBearField {
        return self.root_nodes;
    }

    fn deinit(self: *const TopTree) void {
        _ = self;
    }
};

fn newTopTree(
    roots: [][8]hash_zig.core.KoalaBearField,
    parameter: [5]hash_zig.core.KoalaBearField,
    rng: *hash_zig.prf.ChaCha12Rng,
    allocator: std.mem.Allocator,
) !TopTree {
    _ = parameter;
    _ = rng;
    _ = allocator;

    var root: [8]hash_zig.core.KoalaBearField = undefined;
    if (roots.len == 0) {
        for (0..8) |i| {
            root[i] = hash_zig.core.KoalaBearField{ .value = 0 };
        }
    } else {
        for (0..8) |i| {
            var accum: u64 = 0;
            for (roots) |r| {
                accum += r[i].value;
            }
            root[i] = hash_zig.core.KoalaBearField{ .value = @as(u32, @intCast(accum % hash_zig.core.KoalaBearField.PRIME)) };
        }
    }

    return TopTree{ .root_nodes = root };
}
