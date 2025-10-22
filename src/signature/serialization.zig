//! Serialization utilities for GeneralizedXMSS signatures and keys
//! Provides JSON-based serialization for cross-compatibility testing

const std = @import("std");
const Allocator = std.mem.Allocator;
const FieldElement = @import("../core/field.zig").FieldElement;
const GeneralizedXMSSSignature = @import("signature_native.zig").GeneralizedXMSSSignature;
const GeneralizedXMSSPublicKey = @import("signature_native.zig").GeneralizedXMSSPublicKey;
const GeneralizedXMSSSecretKey = @import("signature_native.zig").GeneralizedXMSSSecretKey;
const HashTreeOpening = @import("signature_native.zig").HashTreeOpening;

/// Serialize a FieldElement to a hex string
pub fn serializeFieldElement(allocator: Allocator, elem: FieldElement) ![]u8 {
    const bytes = elem.toBytes();
    return try std.fmt.allocPrint(allocator, "0x{x:0>8}", .{std.mem.readInt(u32, &bytes, .little)});
}

/// Deserialize a FieldElement from a hex string
pub fn deserializeFieldElement(hex_str: []const u8) !FieldElement {
    // Remove 0x prefix if present
    const clean_hex = if (std.mem.startsWith(u8, hex_str, "0x")) hex_str[2..] else hex_str;

    const value = try std.fmt.parseInt(u32, clean_hex, 16);
    return FieldElement.fromU32(value);
}

/// Serialize a FieldElement array to JSON array of hex strings
pub fn serializeFieldElementArray(allocator: Allocator, elements: []const FieldElement) ![]u8 {
    var json_parts = std.ArrayList([]u8).init(allocator);
    defer {
        for (json_parts.items) |part| allocator.free(part);
        json_parts.deinit();
    }

    for (elements) |elem| {
        const hex_str = try serializeFieldElement(allocator, elem);
        try json_parts.append(hex_str);
    }

    var result = std.ArrayList(u8).init(allocator);
    defer result.deinit();

    try result.append('[');
    for (json_parts.items, 0..) |part, i| {
        if (i > 0) try result.append(',');
        try result.append('"');
        try result.appendSlice(part);
        try result.append('"');
    }
    try result.append(']');

    return result.toOwnedSlice();
}

/// Deserialize a FieldElement array from JSON array of hex strings
pub fn deserializeFieldElementArray(allocator: Allocator, json_str: []const u8) ![]FieldElement {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, json_str, .{}) catch |err| {
        std.debug.print("JSON parse error: {}\n", .{err});
        return err;
    };
    defer parsed.deinit();

    if (parsed.value != .array) {
        return error.InvalidJsonFormat;
    }

    const elements = try allocator.alloc(FieldElement, parsed.value.array.items.len);
    for (parsed.value.array.items, 0..) |item, i| {
        if (item != .string) {
            return error.InvalidJsonFormat;
        }
        elements[i] = try deserializeFieldElement(item.string);
    }

    return elements;
}

/// Serialize a GeneralizedXMSSSignature to JSON
pub fn serializeSignature(allocator: Allocator, signature: *const GeneralizedXMSSSignature) ![]u8 {
    var result = std.ArrayList(u8).init(allocator);
    defer result.deinit();

    try result.appendSlice("{");

    // Serialize path using controlled access
    const path = signature.getPath();
    try result.appendSlice("\"path\":{");
    try result.appendSlice("\"nodes\":");
    const path_json = try serializeFieldElementArray(allocator, path.path);
    defer allocator.free(path_json);
    try result.appendSlice(path_json);
    try result.appendSlice("}");

    // Serialize rho using controlled access
    try result.appendSlice(",\"rho\":");
    const rho = signature.getRho();
    const rho_json = try serializeFieldElementArray(allocator, &rho);
    defer allocator.free(rho_json);
    try result.appendSlice(rho_json);

    // Serialize hashes using controlled access
    try result.appendSlice(",\"hashes\":");
    const hashes = signature.getHashes();
    const hashes_json = try serializeFieldElementArray(allocator, hashes);
    defer allocator.free(hashes_json);
    try result.appendSlice(hashes_json);

    try result.appendSlice("}");

    return result.toOwnedSlice();
}

/// Deserialize a GeneralizedXMSSSignature from JSON
pub fn deserializeSignature(allocator: Allocator, json_str: []const u8) !*GeneralizedXMSSSignature {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, json_str, .{}) catch |err| {
        std.debug.print("JSON parse error: {}\n", .{err});
        return err;
    };
    defer parsed.deinit();

    if (parsed.value != .object) {
        return error.InvalidJsonFormat;
    }

    const obj = parsed.value.object;

    // Parse path
    const path_obj = obj.get("path") orelse return error.MissingPathField;
    if (path_obj != .object) return error.InvalidJsonFormat;

    const nodes_array = path_obj.object.get("nodes") orelse return error.MissingNodesField;
    if (nodes_array != .array) return error.InvalidJsonFormat;

    const path_elements = try allocator.alloc(FieldElement, nodes_array.array.items.len);
    for (nodes_array.array.items, 0..) |item, i| {
        if (item != .string) return error.InvalidJsonFormat;
        path_elements[i] = try deserializeFieldElement(item.string);
    }

    const path = try HashTreeOpening.init(allocator, path_elements);

    // Parse rho
    const rho_array = obj.get("rho") orelse return error.MissingRhoField;
    if (rho_array != .array or rho_array.array.items.len != 7) return error.InvalidJsonFormat;

    var rho: [7]FieldElement = undefined;
    for (rho_array.array.items, 0..) |item, i| {
        if (item != .string) return error.InvalidJsonFormat;
        rho[i] = try deserializeFieldElement(item.string);
    }

    // Parse hashes
    const hashes_array = obj.get("hashes") orelse return error.MissingHashesField;
    if (hashes_array != .array) return error.InvalidJsonFormat;

    const hash_elements = try allocator.alloc(FieldElement, hashes_array.array.items.len);
    for (hashes_array.array.items, 0..) |item, i| {
        if (item != .string) return error.InvalidJsonFormat;
        hash_elements[i] = try deserializeFieldElement(item.string);
    }

    return try GeneralizedXMSSSignature.init(allocator, path, rho, hash_elements);
}

/// Serialize a GeneralizedXMSSPublicKey to JSON
pub fn serializePublicKey(allocator: Allocator, public_key: *const GeneralizedXMSSPublicKey) ![]u8 {
    var result = std.ArrayList(u8).init(allocator);
    defer result.deinit();

    try result.appendSlice("{");

    // Serialize root using controlled access
    const root = public_key.getRoot();
    const root_hex = try serializeFieldElement(allocator, root);
    defer allocator.free(root_hex);
    try result.appendSlice("\"root\":");
    try result.appendSlice(root_hex);

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
        std.debug.print("JSON parse error: {}\n", .{err});
        return err;
    };
    defer parsed.deinit();

    if (parsed.value != .object) {
        return error.InvalidJsonFormat;
    }

    const obj = parsed.value.object;

    // Parse root
    const root_obj = obj.get("root") orelse return error.MissingRootField;
    if (root_obj != .string) return error.InvalidJsonFormat;
    const root = try deserializeFieldElement(root_obj.string);

    // Parse parameter
    const param_array = obj.get("parameter") orelse return error.MissingParameterField;
    if (param_array != .array or param_array.array.items.len != 5) return error.InvalidJsonFormat;

    var parameter: [5]FieldElement = undefined;
    for (param_array.array.items, 0..) |item, i| {
        if (item != .string) return error.InvalidJsonFormat;
        parameter[i] = try deserializeFieldElement(item.string);
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
    std.debug.print("Generated JSON: {s}\n", .{serialized});

    const deserialized = try deserializeFieldElementArray(allocator, serialized);
    defer allocator.free(deserialized);

    try std.testing.expectEqual(original.len, deserialized.len);
    for (original, deserialized) |orig, deser| {
        try std.testing.expect(orig.eql(deser));
    }
}
