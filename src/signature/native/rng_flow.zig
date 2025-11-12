const std = @import("std");
const FieldElement = @import("../../core/field.zig").FieldElement;
const ShakePRFtoF_8_7 = @import("../../prf/shake_prf_to_field.zig").ShakePRFtoF_8_7;
const ShakePRFtoF_7_6 = @import("../../prf/shake_prf_to_field.zig").ShakePRFtoF_7_6;

const MESSAGE_LENGTH: usize = 32;

pub fn generateRandomParameter(self: anytype) ![5]FieldElement {
    var parameter: [5]FieldElement = undefined;
    var random_bytes: [20]u8 = undefined;
    peekRngBytes(self, &random_bytes);

    for (0..5) |i| {
        const random_value = std.mem.readInt(u32, random_bytes[i * 4 ..][0..4], .little);
        const canonical = random_value >> 1;
        parameter[i] = FieldElement.fromCanonical(canonical);
    }

    return parameter;
}

pub fn generateRandomPRFKey(self: anytype) ![32]u8 {
    var prf_key: [32]u8 = undefined;
    self.rng.fill(&prf_key);
    return prf_key;
}

pub fn generateRandomDomain(self: anytype, count: usize) ![8]FieldElement {
    var result: [8]FieldElement = undefined;
    const hash_len = self.lifetime_params.hash_len_fe;
    const fill_count = @min(count, hash_len);

    for (0..fill_count) |i| {
        const random_value = self.rng.random().int(u32);
        result[i] = FieldElement.fromCanonical(random_value >> 1);
    }

    for (fill_count..8) |i| {
        result[i] = FieldElement.zero();
    }

    return result;
}

pub fn generateRandomDomainSingle(self: anytype) ![8]FieldElement {
    return generateRandomDomainSingleWithRng(self, &self.rng.random());
}

pub fn generateRandomDomainSingleWithRng(self: anytype, rng: *const std.Random) ![8]FieldElement {
    var result: [8]FieldElement = undefined;
    const hash_len = self.lifetime_params.hash_len_fe;
    var random_bytes: [32]u8 = undefined;
    rng.bytes(&random_bytes);

    for (0..hash_len) |i| {
        const random_value = std.mem.readInt(u32, random_bytes[i * 4 ..][0..4], .little);
        result[i] = FieldElement.fromCanonical(random_value >> 1);
    }

    for (hash_len..8) |i| {
        result[i] = FieldElement.zero();
    }

    return result;
}

pub fn generateRandomness(
    self: anytype,
    prf_key: [32]u8,
    epoch: u32,
    message: [MESSAGE_LENGTH]u8,
    counter: u64,
) ![]FieldElement {
    const rand_len = self.lifetime_params.rand_len_fe;
    var rho = try self.allocator.alloc(FieldElement, rand_len);

    switch (rand_len) {
        6 => {
            const raw = ShakePRFtoF_7_6.getRandomness(prf_key, epoch, &message, counter);
            for (raw, 0..) |val, i| {
                rho[i] = FieldElement.fromMontgomery(val);
            }
        },
        else => {
            const raw = ShakePRFtoF_8_7.getRandomness(prf_key, epoch, &message, counter);
            for (raw, 0..) |val, i| {
                rho[i] = FieldElement.fromMontgomery(val);
            }
        },
    }

    return rho;
}

fn peekRngBytes(self: anytype, buf: []u8) void {
    const bytes = &self.rng.state;
    const avail = bytes.len - self.rng.offset;

    if (avail >= buf.len) {
        @memcpy(buf, bytes[self.rng.offset..][0..buf.len]);
        return;
    }

    if (avail > 0) {
        @memcpy(buf[0..avail], bytes[self.rng.offset..]);
    }

    @memset(buf[avail..], 0);
}
