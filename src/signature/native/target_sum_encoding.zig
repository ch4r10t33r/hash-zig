const std = @import("std");
const log = @import("../../utils/log.zig");
const FieldElement = @import("../../core/field.zig").FieldElement;
const poseidon_top_level = @import("poseidon_top_level.zig");

const MESSAGE_LENGTH: usize = 32;

pub fn deriveTargetSumEncoding(
    self: anytype,
    parameter: [5]FieldElement,
    epoch: u32,
    randomness: []const FieldElement,
    message: [MESSAGE_LENGTH]u8,
) ![]u8 {
    const dimension: usize = self.lifetime_params.dimension;
    const expected_sum: usize = self.lifetime_params.target_sum;

    const chunks = try poseidon_top_level.applyTopLevelPoseidonMessageHash(self, parameter, epoch, randomness, message);
    defer self.allocator.free(chunks);

    var sum: usize = 0;
    for (chunks) |chunk| {
        sum += chunk;
    }

    if (sum != expected_sum) {
        log.print("ZIG_ENCODING_CHUNKS_FAIL:", .{});
        for (chunks) |chunk| {
            log.print(" {d}", .{chunk});
        }
        log.print(" sum={} expected={}\n", .{ sum, expected_sum });
        return error.EncodingSumMismatch;
    }

    log.print("ZIG_ENCODING_CHUNKS_FINAL:", .{});
    for (chunks) |chunk| {
        log.print(" {d}", .{chunk});
    }
    log.print("\n", .{});

    const x = try self.allocator.alloc(u8, dimension);
    @memcpy(x, chunks[0..dimension]);

    return x;
}
