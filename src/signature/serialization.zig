//! Serialization utilities for GeneralizedXMSS signatures and keys
//! Provides JSON-based serialization for cross-compatibility testing

const std = @import("std");
const log = @import("../utils/log.zig");
const Allocator = std.mem.Allocator;
const FieldElement = @import("../core/field.zig").FieldElement;
const GeneralizedXMSSSignature = @import("signature_native.zig").GeneralizedXMSSSignature;
const GeneralizedXMSSPublicKey = @import("signature_native.zig").GeneralizedXMSSPublicKey;
const GeneralizedXMSSSecretKey = @import("signature_native.zig").GeneralizedXMSSSecretKey;
const HashTreeOpening = @import("signature_native.zig").HashTreeOpening;

fn fromMontgomeryValue(value: u32) FieldElement {
    return FieldElement.fromMontgomery(value);
}

/// Serialize a FieldElement to a decimal string (Montgomery residue)
pub fn serializeFieldElement(allocator: Allocator, elem: FieldElement) ![]u8 {
    return try std.fmt.allocPrint(allocator, "{}", .{elem.toMontgomery()});
}

/// Deserialize a FieldElement from a hex string
pub fn deserializeFieldElement(hex_str: []const u8) !FieldElement {
    const clean_hex = if (std.mem.startsWith(u8, hex_str, "0x") or std.mem.startsWith(u8, hex_str, "0X"))
        hex_str[2..]
    else
        hex_str;

    const value = try std.fmt.parseInt(u32, clean_hex, 16);
    return FieldElement.fromMontgomery(value);
}

/// Flexibly parse a FieldElement from a generic JSON value.
/// Accepts:
/// - string: hex (with or without 0x) or decimal
/// - integer/number
/// - object: tries common wrappers like {"value": X} or single-field unwrap
/// - array of length 1: unwrap first element
fn parseFieldElementFromJsonValue(val: std.json.Value) !FieldElement {
    switch (val) {
        .string => |s| {
            if (std.mem.startsWith(u8, s, "0x") or std.mem.startsWith(u8, s, "0X")) {
                return deserializeFieldElement(s);
            }
            // Interpret decimal or plain-hex strings as Montgomery values
            if (std.fmt.parseInt(u32, s, 10)) |dec| {
                return FieldElement.fromMontgomery(dec);
            } else |_| {}
            const value = try std.fmt.parseInt(u32, s, 16);
            return FieldElement.fromMontgomery(value);
        },
        .integer => |i| {
            if (i < 0) return error.InvalidJsonFormat;
            const as_u64: u64 = @intCast(i);
            const as_u32: u32 = @intCast(@min(as_u64, @as(u64, std.math.maxInt(u32))));
            return FieldElement.fromMontgomery(as_u32);
        },
        .float => |f| {
            const clamped: f64 = if (f < 0) 0 else f;
            const as_u32: u32 = @intFromFloat(@min(clamped, @as(f64, @floatFromInt(std.math.maxInt(u32)))));
            return FieldElement.fromMontgomery(as_u32);
        },
        .object => |o| {
            if (o.get("value")) |inner| {
                return parseFieldElementFromJsonValue(inner);
            }
            // if single-field object, unwrap its first value
            if (o.count() == 1) {
                var it = o.iterator();
                if (it.next()) |entry| {
                    return parseFieldElementFromJsonValue(entry.value_ptr.*);
                }
            }
            return error.InvalidJsonFormat;
        },
        .array => |arr| {
            if (arr.items.len == 1) {
                return parseFieldElementFromJsonValue(arr.items[0]);
            }
            return error.InvalidJsonFormat;
        },
        else => return error.InvalidJsonFormat,
    }
}

/// Serialize a FieldElement array to JSON array of decimal numbers
pub fn serializeFieldElementArray(allocator: Allocator, elements: []const FieldElement) ![]u8 {
    var result = std.ArrayList(u8).init(allocator);
    defer result.deinit();

    try result.append('[');
    for (elements, 0..) |elem, i| {
        if (i > 0) try result.append(',');
        const value_str = try serializeFieldElement(allocator, elem);
        defer allocator.free(value_str);
        try result.appendSlice(value_str);
    }
    try result.append(']');

    return result.toOwnedSlice();
}

/// Deserialize a FieldElement array from JSON array of hex strings
pub fn deserializeFieldElementArray(allocator: Allocator, json_str: []const u8) ![]FieldElement {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, json_str, .{}) catch |err| {
        log.print("JSON parse error: {}\n", .{err});
        return err;
    };
    defer parsed.deinit();

    if (parsed.value != .array) {
        return error.InvalidJsonFormat;
    }

    const elements = try allocator.alloc(FieldElement, parsed.value.array.items.len);
    for (parsed.value.array.items, 0..) |item, i| {
        elements[i] = try parseFieldElementFromJsonValue(item);
    }

    return elements;
}

/// Serialize a GeneralizedXMSSSignature to JSON
pub fn serializeSignature(allocator: Allocator, signature: *const GeneralizedXMSSSignature) ![]u8 {
    var result = std.ArrayList(u8).init(allocator);
    defer result.deinit();

    try result.appendSlice("{");

    // Serialize path using controlled access as array of 8-element arrays
    const path = signature.getPath();
    try result.appendSlice("\"path\":{");
    try result.appendSlice("\"nodes\":");
    var nodes_str = std.ArrayList(u8).init(allocator);
    defer nodes_str.deinit();
    try nodes_str.append('[');
    const nodes = path.getNodes();
    for (nodes, 0..) |node, i| {
        if (i > 0) try nodes_str.append(',');
        try nodes_str.append('[');
        for (node, 0..) |fe, j| {
            if (j > 0) try nodes_str.append(',');
            const value_str = try serializeFieldElement(allocator, fe);
            defer allocator.free(value_str);
            try nodes_str.appendSlice(value_str);
        }
        try nodes_str.append(']');
    }
    try nodes_str.append(']');
    const nodes_slice = try nodes_str.toOwnedSlice();
    defer allocator.free(nodes_slice);
    try result.appendSlice(nodes_slice);
    try result.appendSlice("}");

    // Serialize rho using controlled access
    try result.appendSlice(",\"rho\":");
    const rho = signature.getRho();
    var rho_json_builder = std.ArrayList(u8).init(allocator);
    defer rho_json_builder.deinit();
    try rho_json_builder.append('[');
    for (&rho, 0..) |fe, i| {
        if (i > 0) try rho_json_builder.append(',');
        const value_str = try serializeFieldElement(allocator, fe);
        defer allocator.free(value_str);
        try rho_json_builder.appendSlice(value_str);
    }
    try rho_json_builder.append(']');
    const rho_json = try rho_json_builder.toOwnedSlice();
    defer allocator.free(rho_json);
    try result.appendSlice(rho_json);

    // Serialize hashes as array of 8-element arrays (domains)
    try result.appendSlice(",\"hashes\":");
    const hashes = signature.getHashes();
    var hashes_str = std.ArrayList(u8).init(allocator);
    defer hashes_str.deinit();
    try hashes_str.append('[');
    for (hashes, 0..) |domain, i| {
        if (i > 0) try hashes_str.append(',');
        try hashes_str.append('[');
        for (domain, 0..) |fe, j| {
            if (j > 0) try hashes_str.append(',');
            const value_str = try serializeFieldElement(allocator, fe);
            defer allocator.free(value_str);
            try hashes_str.appendSlice(value_str);
        }
        try hashes_str.append(']');
    }
    try hashes_str.append(']');
    const hashes_slice = try hashes_str.toOwnedSlice();
    defer allocator.free(hashes_slice);
    try result.appendSlice(hashes_slice);

    try result.appendSlice("}");

    return result.toOwnedSlice();
}

/// Deserialize a GeneralizedXMSSSignature from JSON
pub fn deserializeSignature(allocator: Allocator, json_str: []const u8) !*GeneralizedXMSSSignature {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, json_str, .{}) catch |err| {
        log.print("JSON parse error: {}\n", .{err});
        return err;
    };
    defer parsed.deinit();

    if (parsed.value != .object) {
        return error.InvalidJsonFormat;
    }

    const obj = parsed.value.object;

    // Parse path (accept multiple Rust/JSON shapes)
    const path_obj = obj.get("path") orelse return error.MissingPathField;
    if (path_obj != .object) return error.InvalidJsonFormat;

    var maybe_nodes: ?std.json.Value = null;
    if (path_obj.object.get("nodes")) |n| {
        maybe_nodes = n;
    } else {
        var it = path_obj.object.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.* == .array) {
                maybe_nodes = entry.value_ptr.*;
                break;
            }
        }
    }
    const nodes_array = maybe_nodes orelse return error.MissingNodesField;
    if (nodes_array != .array) return error.InvalidJsonFormat;

    // Expect array of arrays where each inner array has 7 or 8 elements (depending on lifetime)
    const path_nodes = try allocator.alloc([8]FieldElement, nodes_array.array.items.len);
    for (nodes_array.array.items, 0..) |node_val, i| {
        if (node_val != .array) return error.InvalidJsonFormat;
        const node_len = node_val.array.items.len;
        if (node_len < 7 or node_len > 8) return error.InvalidJsonFormat;

        // Copy node elements (7 or 8)
        for (0..node_len) |j| {
            path_nodes[i][j] = try parseFieldElementFromJsonValue(node_val.array.items[j]);
        }
        // Pad with zeros if node has 7 elements (for lifetime 2^18)
        for (node_len..8) |j| {
            path_nodes[i][j] = FieldElement{ .value = 0 };
        }
    }

    errdefer allocator.free(path_nodes);
    const path = try HashTreeOpening.init(allocator, path_nodes);
    allocator.free(path_nodes);

    // Parse rho (6 for lifetime 2^18, 7 for lifetime 2^8)
    const rho_array = obj.get("rho") orelse return error.MissingRhoField;
    if (rho_array != .array) return error.InvalidJsonFormat;
    const rho_len = rho_array.array.items.len;
    if (rho_len < 6 or rho_len > 7) return error.InvalidJsonFormat;

    var rho: [7]FieldElement = undefined;
    for (0..rho_len) |i| {
        rho[i] = try parseFieldElementFromJsonValue(rho_array.array.items[i]);
    }
    // Pad with zeros if rho has 6 elements (for lifetime 2^18)
    for (rho_len..7) |i| {
        rho[i] = FieldElement{ .value = 0 };
    }

    // Parse hashes as array of arrays (7 or 8 elements depending on lifetime)
    // Hash length can vary: 7 for lifetime 2^18, 8 for lifetime 2^8
    const hashes_array = obj.get("hashes") orelse return error.MissingHashesField;
    if (hashes_array != .array) return error.InvalidJsonFormat;

    const hashes_domains = try allocator.alloc([8]FieldElement, hashes_array.array.items.len);
    for (hashes_array.array.items, 0..) |domain_val, i| {
        if (domain_val != .array) return error.InvalidJsonFormat;
        const domain_len = domain_val.array.items.len;
        if (domain_len < 7 or domain_len > 8) return error.InvalidJsonFormat;

        // Copy domain elements (7 or 8)
        for (0..domain_len) |j| {
            hashes_domains[i][j] = try parseFieldElementFromJsonValue(domain_val.array.items[j]);
        }
        // Pad with zeros if domain has 7 elements (for lifetime 2^18)
        for (domain_len..8) |j| {
            hashes_domains[i][j] = FieldElement{ .value = 0 };
        }
    }

    errdefer allocator.free(hashes_domains);
    const signature = try GeneralizedXMSSSignature.initDeserialized(allocator, path, rho, hashes_domains);
    allocator.free(hashes_domains);
    return signature;
}

/// Serialize a GeneralizedXMSSPublicKey to JSON
pub fn serializePublicKey(allocator: Allocator, public_key: *const GeneralizedXMSSPublicKey) ![]u8 {
    var result = std.ArrayList(u8).init(allocator);
    defer result.deinit();

    try result.appendSlice("{");

    // Serialize root using controlled access (as array to match Rust)
    const root = public_key.getRoot();
    const root_json = try serializeFieldElementArray(allocator, &root);
    defer allocator.free(root_json);
    try result.appendSlice("\"root\":");
    try result.appendSlice(root_json);

    // Serialize parameter using controlled access
    try result.appendSlice(",\"parameter\":");
    const parameter = public_key.getParameter();
    const param_json = try serializeFieldElementArray(allocator, &parameter);
    defer allocator.free(param_json);
    try result.appendSlice(param_json);

    try result.appendSlice("}");

    return result.toOwnedSlice();
}

/// Deserialize a GeneralizedXMSSPublicKey from JSON
pub fn deserializePublicKey(json_str: []const u8) !GeneralizedXMSSPublicKey {
    var parsed = std.json.parseFromSlice(std.json.Value, std.heap.page_allocator, json_str, .{}) catch |err| {
        log.print("JSON parse error: {}\n", .{err});
        return err;
    };
    defer parsed.deinit();

    if (parsed.value != .object) {
        return error.InvalidJsonFormat;
    }

    const obj = parsed.value.object;

    // Parse root (as array to match Rust)
    // Root length can vary: 7 for lifetime 2^18, 8 for lifetime 2^8
    const root_array = obj.get("root") orelse return error.MissingRootField;
    if (root_array != .array) return error.InvalidJsonFormat;
    const root_len = root_array.array.items.len;
    if (root_len < 7 or root_len > 8) return error.InvalidJsonFormat;

    var root: [8]FieldElement = undefined;
    // Copy root elements (7 or 8)
    for (0..root_len) |i| {
        root[i] = try parseFieldElementFromJsonValue(root_array.array.items[i]);
    }
    // Pad with zeros if root has 7 elements (for lifetime 2^18)
    for (root_len..8) |i| {
        root[i] = FieldElement{ .value = 0 };
    }

    // Parse parameter
    const param_array = obj.get("parameter") orelse return error.MissingParameterField;
    if (param_array != .array or param_array.array.items.len != 5) return error.InvalidJsonFormat;

    var parameter: [5]FieldElement = undefined;
    for (param_array.array.items, 0..) |item, i| {
        parameter[i] = try parseFieldElementFromJsonValue(item);
    }

    return GeneralizedXMSSPublicKey.init(root, parameter);
}

/// Serialize a secret key (simplified - just the essential data for testing)
pub fn serializeSecretKey(allocator: Allocator, secret_key: *const GeneralizedXMSSSecretKey) ![]u8 {
    var result = std.ArrayList(u8).init(allocator);
    defer result.deinit();

    try result.appendSlice("{");

    // Serialize PRF key using controlled access
    const prf_key = secret_key.getPrfKey();
    const prf_key_hex = try std.fmt.allocPrint(allocator, "0x{x:0>64}", .{std.fmt.fmtSliceHexLower(&prf_key)});
    defer allocator.free(prf_key_hex);
    try result.appendSlice("\"prf_key\":");
    try result.appendSlice(prf_key_hex);

    // Serialize activation parameters using controlled access
    try result.appendSlice(",\"activation_epoch\":");
    const activation_epoch = secret_key.getActivationEpoch();
    const epoch_str = try std.fmt.allocPrint(allocator, "{}", .{activation_epoch});
    defer allocator.free(epoch_str);
    try result.appendSlice(epoch_str);

    try result.appendSlice(",\"num_active_epochs\":");
    const num_active_epochs = secret_key.getNumActiveEpochs();
    const epochs_str = try std.fmt.allocPrint(allocator, "{}", .{num_active_epochs});
    defer allocator.free(epochs_str);
    try result.appendSlice(epochs_str);

    // Serialize parameter using controlled access
    try result.appendSlice(",\"parameter\":");
    const parameter = secret_key.getParameter();
    const param_json = try serializeFieldElementArray(allocator, &parameter);
    defer allocator.free(param_json);
    try result.appendSlice(param_json);

    try result.appendSlice("}");

    return result.toOwnedSlice();
}

// Test functions
test "serialize and deserialize FieldElement" {
    const allocator = std.testing.allocator;
    const original = FieldElement.fromU32(0x12345678);

    const serialized = try serializeFieldElement(allocator, original);
    defer allocator.free(serialized);

    const deserialized = try deserializeFieldElement(serialized);

    try std.testing.expect(original.eql(deserialized));
}

test "serialize and deserialize FieldElement array" {
    const allocator = std.testing.allocator;
    const original = [_]FieldElement{
        FieldElement.fromU32(0x11111111),
        FieldElement.fromU32(0x22222222),
        FieldElement.fromU32(0x33333333),
    };

    const serialized = try serializeFieldElementArray(allocator, &original);
    defer allocator.free(serialized);

    // Debug: print the generated JSON
    log.print("Generated JSON: {s}\n", .{serialized});

    const deserialized = try deserializeFieldElementArray(allocator, serialized);
    defer allocator.free(deserialized);

    try std.testing.expectEqual(original.len, deserialized.len);
    for (original, deserialized) |orig, deser| {
        try std.testing.expect(orig.eql(deser));
    }
}
