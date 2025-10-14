const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const enable_docs = b.option(bool, "docs", "Enable docs generation") orelse false;

    // Get the poseidon dependency
    const poseidon_dep = b.dependency("poseidon", .{
        .target = target,
        .optimize = optimize,
    });
    const poseidon_mod = poseidon_dep.module("poseidon");

    // Create the module
    const hash_zig_module = b.addModule("hash-zig", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Add poseidon module to hash-zig module
    hash_zig_module.addImport("poseidon", poseidon_mod);

    // Library
    const lib = b.addLibrary(.{
        .name = "hash-zig",
        .linkage = .static,
        .root_module = hash_zig_module,
    });
    b.installArtifact(lib);

    // Lint (using built-in formatter in check mode)
    const lint_cmd = b.addSystemCommand(&.{ "zig", "fmt", "--check", "src", "examples" });
    const lint_step = b.step("lint", "Run lint (zig fmt --check)");
    lint_step.dependOn(&lint_cmd.step);

    // Tests
    const lib_unit_tests = b.addTest(.{
        .root_module = hash_zig_module,
    });
    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);

    // Performance tests (key generation, sign, verify with benchmarks)
    const performance_tests = b.addTest(.{
        .root_source_file = b.path("test/performance_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    performance_tests.root_module.addImport("hash-zig", hash_zig_module);
    const run_performance_tests = b.addRunArtifact(performance_tests);

    // Rust compatibility tests (CRITICAL - must pass)
    const rust_compat_tests = b.addTest(.{
        .root_source_file = b.path("test/rust_compatibility_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    rust_compat_tests.root_module.addImport("hash-zig", hash_zig_module);
    const run_rust_compat_tests = b.addRunArtifact(rust_compat_tests);

    // Test step runs all tests
    const test_step = b.step("test", "Run all tests (MUST pass before merge)");
    test_step.dependOn(&run_lib_unit_tests.step);
    test_step.dependOn(&run_performance_tests.step);
    test_step.dependOn(&run_rust_compat_tests.step);

    // Rust compatibility test step (for CI)
    const rust_test_step = b.step("test-rust-compat", "Run ONLY Rust compatibility tests (for CI)");
    rust_test_step.dependOn(&run_rust_compat_tests.step);

    // Example executable module
    const example_module = b.createModule(.{
        .root_source_file = b.path("examples/basic_usage.zig"),
        .target = target,
        .optimize = optimize,
    });
    example_module.addImport("hash-zig", hash_zig_module);

    const example = b.addExecutable(.{
        .name = "hash-zig-example",
        .root_module = example_module,
    });
    b.installArtifact(example);

    const run_example = b.addRunArtifact(example);
    const example_step = b.step("example", "Run example");
    example_step.dependOn(&run_example.step);

    // Run step (alias for example)
    const run_step = b.step("run", "Run the example application");
    run_step.dependOn(&run_example.step);

    // Benchmark executable
    const benchmark_module = b.createModule(.{
        .root_source_file = b.path("scripts/benchmark.zig"),
        .target = target,
        .optimize = optimize,
    });
    benchmark_module.addImport("hash-zig", hash_zig_module);

    const benchmark = b.addExecutable(.{
        .name = "hash-zig-benchmark",
        .root_module = benchmark_module,
    });
    b.installArtifact(benchmark);

    const run_benchmark = b.addRunArtifact(benchmark);
    const benchmark_step = b.step("benchmark", "Run performance benchmark");
    benchmark_step.dependOn(&run_benchmark.step);

    // SIMD modules, benchmark, and comparison removed - they depended on the local
    // poseidon2 implementation which has been replaced with external zig-poseidon

    // Poseidon2 compatibility test
    const test_p2_module = b.createModule(.{
        .root_source_file = b.path("test_poseidon2_compat.zig"),
        .target = target,
        .optimize = optimize,
    });
    test_p2_module.addImport("poseidon", poseidon_mod);

    const test_p2 = b.addExecutable(.{
        .name = "test-poseidon2-compat",
        .root_module = test_p2_module,
    });
    b.installArtifact(test_p2);

    const run_test_p2 = b.addRunArtifact(test_p2);
    const test_p2_step = b.step("test-p2", "Test Poseidon2 compatibility");
    test_p2_step.dependOn(&run_test_p2.step);

    // Documentation (opt-in to avoid enabling -femit-docs on default builds)
    if (enable_docs) {
        const docs_step = b.step("docs", "Generate documentation");
        const install_docs = b.addInstallDirectory(.{
            .source_dir = lib.getEmittedDocs(),
            .install_dir = .prefix,
            .install_subdir = "docs",
        });
        docs_step.dependOn(&install_docs.step);
    }
}
