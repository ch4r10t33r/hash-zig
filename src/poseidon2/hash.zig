//! Poseidon2 hash function implementation

const std = @import("std");
const field = @import("field.zig");
const FieldElement = field.FieldElement;
const params = @import("../params.zig");
const SecurityLevel = params.SecurityLevel;
const Allocator = std.mem.Allocator;

pub const Poseidon2 = struct {
    state_width: usize,
    rounds_f: usize,
    rounds_p: usize,
    round_constants: []FieldElement,
    mds_matrix: [][]FieldElement,
    security_level: SecurityLevel,

    pub fn init(allocator: Allocator, security_level: SecurityLevel) !Poseidon2 {
        const Config = struct {
            state_width: usize,
            rounds_f: usize,
            rounds_p: usize,
        };

        const config = switch (security_level) {
            .level_128 => Config{ .state_width = 3, .rounds_f = 8, .rounds_p = 56 },
            .level_192 => Config{ .state_width = 4, .rounds_f = 8, .rounds_p = 57 },
            .level_256 => Config{ .state_width = 5, .rounds_f = 8, .rounds_p = 60 },
        };

        const total_rounds = config.rounds_f + config.rounds_p;
        var round_constants = try allocator.alloc(FieldElement, total_rounds * config.state_width);

        var seed: u256 = 0x123456789ABCDEF;
        for (0..round_constants.len) |i| {
            seed = @mod(seed *% 0x5DEECE66D +% 0xB, FieldElement.modulus);
            round_constants[i] = FieldElement.init(seed);
        }

        var mds_matrix = try allocator.alloc([]FieldElement, config.state_width);
        for (0..config.state_width) |i| {
            mds_matrix[i] = try allocator.alloc(FieldElement, config.state_width);
            for (0..config.state_width) |j| {
                const x_i = FieldElement.init(@as(u256, i));
                const y_j = FieldElement.init(@as(u256, j + config.state_width));
                mds_matrix[i][j] = x_i.add(y_j);
            }
        }

        return .{
            .state_width = config.state_width,
            .rounds_f = config.rounds_f,
            .rounds_p = config.rounds_p,
            .round_constants = round_constants,
            .mds_matrix = mds_matrix,
            .security_level = security_level,
        };
    }

    pub fn deinit(self: *Poseidon2, allocator: Allocator) void {
        allocator.free(self.round_constants);
        for (self.mds_matrix) |row| {
            allocator.free(row);
        }
        allocator.free(self.mds_matrix);
    }

    fn sbox(self: Poseidon2, x: FieldElement) FieldElement {
        _ = self;
        return x.pow(5);
    }

    fn fullRound(self: *Poseidon2, state: []FieldElement, round: usize) void {
        for (state, 0..) |*s, i| {
            s.* = s.add(self.round_constants[round * self.state_width + i]);
        }

        for (state) |*s| {
            s.* = self.sbox(s.*);
        }

        self.applyMDS(state);
    }

    fn partialRound(self: *Poseidon2, state: []FieldElement, round: usize) void {
        for (state, 0..) |*s, i| {
            s.* = s.add(self.round_constants[round * self.state_width + i]);
        }

        state[0] = self.sbox(state[0]);
        self.applyMDS(state);
    }

    fn applyMDS(self: *Poseidon2, state: []FieldElement) void {
        var new_state = std.mem.zeroes([8]FieldElement);

        for (0..self.state_width) |i| {
            var sum = FieldElement.init(0);
            for (0..self.state_width) |j| {
                sum = sum.add(self.mds_matrix[i][j].mul(state[j]));
            }
            new_state[i] = sum;
        }

        @memcpy(state[0..self.state_width], new_state[0..self.state_width]);
    }

    pub fn hash(self: *Poseidon2, inputs: []const FieldElement) FieldElement {
        var state = std.mem.zeroes([8]FieldElement);
        state[0] = FieldElement.init(0);

        const input_count = @min(inputs.len, self.state_width - 1);
        @memcpy(state[1 .. 1 + input_count], inputs[0..input_count]);

        for (0..self.rounds_f / 2) |r| {
            self.fullRound(state[0..self.state_width], r);
        }

        for (0..self.rounds_p) |r| {
            self.partialRound(state[0..self.state_width], self.rounds_f / 2 + r);
        }

        for (0..self.rounds_f / 2) |r| {
            self.fullRound(state[0..self.state_width], self.rounds_f / 2 + self.rounds_p + r);
        }

        return state[0];
    }

    pub fn hashBytes(self: *Poseidon2, allocator: Allocator, data: []const u8) ![]u8 {
        const num_elements = (data.len + 31) / 32;
        var elements = try allocator.alloc(FieldElement, num_elements);
        defer allocator.free(elements);

        for (0..num_elements) |i| {
            const start = i * 32;
            const end = @min(start + 32, data.len);
            var chunk: [32]u8 = [_]u8{0} ** 32;
            @memcpy(chunk[0 .. end - start], data[start..end]);
            elements[i] = FieldElement.fromBytes(&chunk);
        }

        const result = self.hash(elements);

        const output_len = switch (self.security_level) {
            .level_128 => @as(usize, 32),
            .level_192 => @as(usize, 48),
            .level_256 => @as(usize, 64),
        };

        var output = try allocator.alloc(u8, output_len);
        var temp_bytes: [32]u8 = undefined;
        result.toBytes(&temp_bytes);

        if (output_len <= 32) {
            @memcpy(output, temp_bytes[0..output_len]);
        } else {
            @memcpy(output[0..32], &temp_bytes);
            const extended_input = try allocator.alloc(FieldElement, 2);
            defer allocator.free(extended_input);
            extended_input[0] = result;
            extended_input[1] = FieldElement.init(1);
            const result2 = self.hash(extended_input);
            result2.toBytes(&temp_bytes);
            @memcpy(output[32..output_len], temp_bytes[0 .. output_len - 32]);
        }

        return output;
    }
};

test "poseidon2 basic hash" {
    const allocator = std.testing.allocator;

    var poseidon = try Poseidon2.init(allocator, .level_128);
    defer poseidon.deinit(allocator);

    var inputs = [_]FieldElement{
        FieldElement.init(1),
        FieldElement.init(2),
    };

    const result = poseidon.hash(&inputs);
    try std.testing.expect(result.value > 0);
}
