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

    // Add test_poseidon2_simple binary
    const test_poseidon2_simple_exe = b.addExecutable(.{
        .name = "test_poseidon2_simple",
        .root_source_file = b.path("src/test_poseidon2_simple.zig"),
        .target = target,
        .optimize = optimize,
    });
    test_poseidon2_simple_exe.root_module.addImport("poseidon", poseidon_mod);
    b.installArtifact(test_poseidon2_simple_exe);

    // Add test_plonky3_compat binary
    const test_plonky3_compat_exe = b.addExecutable(.{
        .name = "test_plonky3_compat",
        .root_source_file = b.path("src/test_plonky3_compat.zig"),
        .target = target,
        .optimize = optimize,
    });
    const poseidon2_compat_mod = b.addModule("poseidon2_compat", .{ .root_source_file = b.path("../../src/poseidon2/root.zig") });
    poseidon2_compat_mod.addImport("poseidon", poseidon_mod);
    test_plonky3_compat_exe.root_module.addImport("poseidon2_compat", poseidon2_compat_mod);
    test_plonky3_compat_exe.root_module.addImport("poseidon", poseidon_mod);
    b.installArtifact(test_plonky3_compat_exe);

    // Add debug_poseidon2 binary
    const debug_poseidon2_exe = b.addExecutable(.{
        .name = "debug_poseidon2",
        .root_source_file = b.path("src/debug_poseidon2.zig"),
        .target = target,
        .optimize = optimize,
    });
    debug_poseidon2_exe.root_module.addImport("poseidon2_compat", poseidon2_compat_mod);
    b.installArtifact(debug_poseidon2_exe);
}
