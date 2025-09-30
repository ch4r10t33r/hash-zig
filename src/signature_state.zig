/// State manager to track which signatures have been used
/// CRITICAL: Must be persisted to prevent signature reuse
pub const SignatureState = struct {
    next_index: u64,
    max_index: u64,

    pub fn init(tree_height: u32) SignatureState {
        return .{
            .next_index = 0,
            .max_index = @as(u64, 1) << @intCast(tree_height),
        };
    }

    pub fn getNextIndex(self: *SignatureState) !u64 {
        if (self.next_index >= self.max_index) {
            return error.NoMoreSignatures;
        }
        const index = self.next_index;
        self.next_index += 1;
        return index;
    }

    pub fn remainingSignatures(self: SignatureState) u64 {
        return self.max_index - self.next_index;
    }

    /// Save state to disk (implement based on your needs)
    pub fn save(self: SignatureState, path: []const u8) !void {
        _ = self;
        _ = path;
        // TODO: Implement persistent storage
        // This is CRITICAL for security - state must survive crashes
    }

    /// Load state from disk
    pub fn load(path: []const u8) !SignatureState {
        _ = path;
        // TODO: Implement loading from persistent storage
        return error.NotImplemented;
    }
};
