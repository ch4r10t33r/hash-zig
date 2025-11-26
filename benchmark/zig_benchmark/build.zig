const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Create hash-zig module directly
    const hash_zig_module = b.addModule("hash-zig", .{
        .root_source_file = b.path("../../src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Removed zig_poseidon dependency - using built-in Poseidon2 implementation

    const exe = b.addExecutable(.{
        .name = "keygen_bench",
        .root_source_file = b.path("src/keygen_bench.zig"),
        .target = target,
        .optimize = optimize,
    });

    exe.root_module.addImport("hash-zig", hash_zig_module);

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the benchmark");
    run_step.dependOn(&run_cmd.step);

}
