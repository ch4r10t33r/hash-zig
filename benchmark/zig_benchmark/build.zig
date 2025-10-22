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

    // Add poseidon dependency
    const zig_poseidon_dep = b.dependency("zig_poseidon", .{
        .target = target,
        .optimize = optimize,
    });
    const poseidon_mod = zig_poseidon_dep.module("poseidon");
    hash_zig_module.addImport("poseidon", poseidon_mod);

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

    // Add signing binary
    const sign_exe = b.addExecutable(.{
        .name = "sign_message",
        .root_source_file = b.path("src/sign_message.zig"),
        .target = target,
        .optimize = optimize,
    });

    sign_exe.root_module.addImport("hash-zig", hash_zig_module);
    b.installArtifact(sign_exe);

    // Add verification binary
    const verify_exe = b.addExecutable(.{
        .name = "verify_signature",
        .root_source_file = b.path("src/verify_signature.zig"),
        .target = target,
        .optimize = optimize,
    });

    verify_exe.root_module.addImport("hash-zig", hash_zig_module);
    b.installArtifact(verify_exe);

    // Add internal test binary
    const test_internal_exe = b.addExecutable(.{
        .name = "test_internal",
        .root_source_file = b.path("src/test_internal.zig"),
        .target = target,
        .optimize = optimize,
    });

    test_internal_exe.root_module.addImport("hash-zig", hash_zig_module);
    b.installArtifact(test_internal_exe);

    // Add same keypair test binary
    const test_same_keypair_exe = b.addExecutable(.{
        .name = "test_same_keypair",
        .root_source_file = b.path("src/test_same_keypair.zig"),
        .target = target,
        .optimize = optimize,
    });

    test_same_keypair_exe.root_module.addImport("hash-zig", hash_zig_module);
    b.installArtifact(test_same_keypair_exe);

    // Add compare_lifetime_2_8 binary
    const compare_exe = b.addExecutable(.{
        .name = "compare_lifetime_2_8",
        .root_source_file = b.path("src/compare_lifetime_2_8.zig"),
        .target = target,
        .optimize = optimize,
    });
    compare_exe.root_module.addImport("hash-zig", hash_zig_module);
    b.installArtifact(compare_exe);
}
