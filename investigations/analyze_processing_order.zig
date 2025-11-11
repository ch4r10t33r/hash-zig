const std = @import("std");
const log = @import("hash-zig").utils.log;
const hash_zig = @import("hash-zig");

const FieldElement = hash_zig.core.FieldElement;
const ChaCha12Rng = hash_zig.prf.ChaCha12Rng;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    log.print("=== ANALYZE PROCESSING ORDER ===\n", .{});
    log.print("Analyzing processing order differences between Rust par_chunks_exact(2) and Zig sequential processing\n", .{});

    // Initialize with same seed
    const seed: [32]u8 = [_]u8{42} ** 32;
    var rng = ChaCha12Rng.init(seed);

    // Generate parameters and PRF key (matching rust_algorithm_port.zig)
    const parameter = try generateParameters(&rng);
    const prf_key = try generatePRFKey(&rng);

    log.print("Parameters: [{}, {}, {}, {}, {}]\n", .{ parameter[0].value, parameter[1].value, parameter[2].value, parameter[3].value, parameter[4].value });
    log.print("PRF key: {x}\n", .{std.fmt.fmtSliceHexLower(&prf_key)});

    // Simulate the top tree building process with detailed logging
    log.print("\n=== SIMULATING TOP TREE BUILDING PROCESS ===\n", .{});

    // Use the actual bottom tree roots from the rust_algorithm_port.zig output
    const bottom_tree_roots = [_][8]FieldElement{
        [_]FieldElement{ FieldElement{ .value = 514807574 }, FieldElement{ .value = 1014712354 }, FieldElement{ .value = 1537374029 }, FieldElement{ .value = 1381830039 }, FieldElement{ .value = 531244209 }, FieldElement{ .value = 763366913 }, FieldElement{ .value = 1306093329 }, FieldElement{ .value = 364527155 } },
        [_]FieldElement{ FieldElement{ .value = 190023107 }, FieldElement{ .value = 1732864846 }, FieldElement{ .value = 2043925309 }, FieldElement{ .value = 1986130035 }, FieldElement{ .value = 1191661769 }, FieldElement{ .value = 127457805 }, FieldElement{ .value = 395239736 }, FieldElement{ .value = 802290173 } },
        [_]FieldElement{ FieldElement{ .value = 1503834228 }, FieldElement{ .value = 562600081 }, FieldElement{ .value = 1531794601 }, FieldElement{ .value = 358794327 }, FieldElement{ .value = 793632936 }, FieldElement{ .value = 772773450 }, FieldElement{ .value = 1311887384 }, FieldElement{ .value = 22827256 } },
        [_]FieldElement{ FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 } },
        [_]FieldElement{ FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 } },
        [_]FieldElement{ FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 } },
        [_]FieldElement{ FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 } },
        [_]FieldElement{ FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 } },
        [_]FieldElement{ FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 } },
        [_]FieldElement{ FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 } },
        [_]FieldElement{ FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 } },
        [_]FieldElement{ FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 } },
        [_]FieldElement{ FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 } },
        [_]FieldElement{ FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 } },
        [_]FieldElement{ FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 } },
        [_]FieldElement{ FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 }, FieldElement{ .value = 0 } },
    };

    // Simulate the top tree building process step by step
    log.print("\n=== TOP TREE BUILDING SIMULATION ===\n", .{});

    // Start with the bottom tree roots (layer 4)
    var current_layer = try allocator.alloc([8]FieldElement, 16);
    defer allocator.free(current_layer);

    for (bottom_tree_roots, 0..) |root, i| {
        current_layer[i] = root;
    }

    log.print("Layer 4 (bottom tree roots): {} nodes\n", .{current_layer.len});
    for (current_layer, 0..) |node, i| {
        log.print("  Node {}: [{}, {}, {}, {}, {}, {}, {}, {}]\n", .{ i, node[0].value, node[1].value, node[2].value, node[3].value, node[4].value, node[5].value, node[6].value, node[7].value });
    }

    // Simulate the tree building process layer by layer
    var current_level: usize = 4;
    while (current_level < 8) : (current_level += 1) {
        log.print("\n--- Building Layer {} -> {} ---\n", .{ current_level, current_level + 1 });

        // Calculate parent layer properties
        const parent_start = 0; // Simplified for this analysis
        const parents_len = current_layer.len / 2;

        log.print("Processing {} pairs to create {} parents\n", .{ current_layer.len, parents_len });

        // Simulate the processing order
        for (0..parents_len) |i| {
            const parent_pos = @as(u32, @intCast(parent_start + i));
            const tweak_level = @as(u8, @intCast(current_level)) + 1;

            log.print("  Pair {}: children [{}] and [{}] -> parent [{}] (tweak_level={}, pos={})\n", .{ i, i * 2, i * 2 + 1, i, tweak_level, parent_pos });
        }

        // Create next layer
        var next_layer = try allocator.alloc([8]FieldElement, parents_len);
        defer allocator.free(next_layer);

        // Simulate parent creation (simplified)
        for (0..parents_len) |i| {
            // Simplified parent creation for analysis
            for (0..8) |j| {
                next_layer[i][j] = FieldElement.fromCanonical(@intCast(current_level * 1000 + i * 8 + j));
            }
        }

        log.print("Layer {}: {} nodes\n", .{ current_level + 1, next_layer.len });
        for (next_layer, 0..) |node, i| {
            log.print("  Node {}: [{}, {}, {}, {}, {}, {}, {}, {}]\n", .{ i, node[0].value, node[1].value, node[2].value, node[3].value, node[4].value, node[5].value, node[6].value, node[7].value });
        }

        // Update current layer
        allocator.free(current_layer);
        current_layer = next_layer;
        // Don't free next_layer here as it becomes current_layer
    }

    log.print("\n=== FINAL RESULT ===\n", .{});
    log.print("Final root: [{}, {}, {}, {}, {}, {}, {}, {}]\n", .{ current_layer[0][0].value, current_layer[0][1].value, current_layer[0][2].value, current_layer[0][3].value, current_layer[0][4].value, current_layer[0][5].value, current_layer[0][6].value, current_layer[0][7].value });

    // Free the final layer
    allocator.free(current_layer);
}

// Helper functions (simplified versions for testing)
fn generateParameters(_: *ChaCha12Rng) ![5]FieldElement {
    return [_]FieldElement{
        FieldElement{ .value = 1128497561 },
        FieldElement{ .value = 1847509114 },
        FieldElement{ .value = 1994249188 },
        FieldElement{ .value = 1874424621 },
        FieldElement{ .value = 1302548296 },
    };
}

fn generatePRFKey(rng: *ChaCha12Rng) ![32]u8 {
    var key: [32]u8 = undefined;
    rng.fill(&key);
    return key;
}
