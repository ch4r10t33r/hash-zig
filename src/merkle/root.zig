// Compatibility root to provide legacy names expected by local imports
const imported = @import("mod.zig");
pub const MerkleTree = imported.MerkleTree;
pub const MerkleTreeNative = imported.MerkleTreeNative;
pub const StreamingTreeBuilder = imported.StreamingTreeBuilder;
pub const IncrementalTreeBuilder = imported.IncrementalTreeBuilder;
pub const params = @import("params.zig");
