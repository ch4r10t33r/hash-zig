const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Add hash-zig dependency
    const hash_zig_dep = b.dependency("hash_zig", .{
        .target = target,
        .optimize = optimize,
    });

    const exe = b.addExecutable(.{
        .name = "keygen_bench",
        .root_source_file = b.path("src/keygen_bench.zig"),
        .target = target,
        .optimize = optimize,
    });

    exe.root_module.addImport("hash-zig", hash_zig_dep.module("hash-zig"));

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

    sign_exe.root_module.addImport("hash-zig", hash_zig_dep.module("hash-zig"));
    b.installArtifact(sign_exe);

    // Add verification binary
    const verify_exe = b.addExecutable(.{
        .name = "verify_signature",
        .root_source_file = b.path("src/verify_signature.zig"),
        .target = target,
        .optimize = optimize,
    });

    verify_exe.root_module.addImport("hash-zig", hash_zig_dep.module("hash-zig"));
    b.installArtifact(verify_exe);

    // Add internal test binary
    const test_internal_exe = b.addExecutable(.{
        .name = "test_internal",
        .root_source_file = b.path("src/test_internal.zig"),
        .target = target,
        .optimize = optimize,
    });

    test_internal_exe.root_module.addImport("hash-zig", hash_zig_dep.module("hash-zig"));
    b.installArtifact(test_internal_exe);

    // Add same keypair test binary
    const test_same_keypair_exe = b.addExecutable(.{
        .name = "test_same_keypair",
        .root_source_file = b.path("src/test_same_keypair.zig"),
        .target = target,
        .optimize = optimize,
    });

    test_same_keypair_exe.root_module.addImport("hash-zig", hash_zig_dep.module("hash-zig"));
    b.installArtifact(test_same_keypair_exe);
}
