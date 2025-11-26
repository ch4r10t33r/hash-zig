const std = @import("std");
const root = @import("root");
const poseidon_top_level = root.signature.native.poseidon_top_level;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Test cases: (w, v, d) combinations that are relevant for our tests
    const test_cases = [_]struct { w: usize, v: usize, d: usize }{
        .{ .w = 8, .v = 1, .d = 0 },
        .{ .w = 8, .v = 1, .d = 5 },
        .{ .w = 8, .v = 1, .d = 7 },
        .{ .w = 8, .v = 2, .d = 0 },
        .{ .w = 8, .v = 2, .d = 5 },
        .{ .w = 8, .v = 2, .d = 10 },
        .{ .w = 8, .v = 2, .d = 14 },
        .{ .w = 8, .v = 64, .d = 0 },
        .{ .w = 8, .v = 64, .d = 50 },
        .{ .w = 8, .v = 64, .d = 71 },
        .{ .w = 8, .v = 64, .d = 100 },
        .{ .w = 8, .v = 64, .d = 200 },
        .{ .w = 8, .v = 64, .d = 300 },
        .{ .w = 8, .v = 64, .d = 400 },
        .{ .w = 8, .v = 64, .d = 448 }, // max_d for v=64, w=8
    };

    const stdout = std.io.getStdOut().writer();
    try stdout.print("Zig Layer Size Values\n", .{});
    try stdout.print("=====================\n", .{});
    try stdout.print("Format: w={{}}, v={{}}, d={{}} -> size\n\n", .{});

    // Create a context to access layer data
    var ctx = try poseidon_top_level.PoseidonTopLevelContext.init(allocator, .{
        .log_lifetime = 8,
        .dimension = 64,
        .base = 8,
        .final_layer = 77,
        .target_sum = 375,
        .parameter_len = 5,
        .tweak_len_fe = 2,
        .msg_len_fe = 9,
        .rand_len_fe = 6,
        .hash_len_fe = 7,
        .capacity = 9,
    });
    defer ctx.deinit();

    for (test_cases) |tc| {
        const w = tc.w;
        const v = tc.v;
        const d = tc.d;

        // Check if d is valid for this dimension
        const max_d = (w - 1) * v;
        if (d > max_d) {
            try stdout.print("w={}, v={}, d={} -> INVALID (max_d={})\n", .{ w, v, d, max_d });
            continue;
        }

        // Get layer data for base w
        const layer_data = try ctx.getLayerData(w);
        const info = layer_data.get(v);

        if (d < info.sizes.len) {
            const size_str = try std.fmt.allocPrint(allocator, "{}", .{info.sizes[d].toConst()});
            defer allocator.free(size_str);
            try stdout.print("w={}, v={}, d={} -> {s}\n", .{ w, v, d, size_str });
        } else {
            try stdout.print("w={}, v={}, d={} -> OUT_OF_BOUNDS (len={})\n", .{ w, v, d, info.sizes.len });
        }
    }
}

