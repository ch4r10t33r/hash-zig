const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const enable_docs = b.option(bool, "docs", "Enable docs generation") orelse false;

    // Get the zig-poseidon dependency
    const zig_poseidon_dep = b.dependency("zig_poseidon", .{
        .target = target,
        .optimize = optimize,
    });
    const poseidon_mod = zig_poseidon_dep.module("poseidon");

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

    // Field-native example executable module
    const example_native_module = b.createModule(.{
        .root_source_file = b.path("examples/basic_usage_native.zig"),
        .target = target,
        .optimize = optimize,
    });
    example_native_module.addImport("hash-zig", hash_zig_module);

    const example_native = b.addExecutable(.{
        .name = "hash-zig-example-native",
        .root_module = example_native_module,
    });
    b.installArtifact(example_native);

    const run_example_native = b.addRunArtifact(example_native);
    const example_native_step = b.step("example-native", "Run field-native (Rust-compatible) example");
    example_native_step.dependOn(&run_example_native.step);

    // Rust compatibility test executable module
    const rust_compat_test_module = b.createModule(.{
        .root_source_file = b.path("examples/rust_compat_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    rust_compat_test_module.addImport("hash-zig", hash_zig_module);

    const rust_compat_test_exe = b.addExecutable(.{
        .name = "rust-compat-test",
        .root_module = rust_compat_test_module,
    });
    b.installArtifact(rust_compat_test_exe);

    const run_rust_compat_test_exe = b.addRunArtifact(rust_compat_test_exe);
    const rust_compat_test_exe_step = b.step("rust-compat-test", "Run Rust cross-implementation compatibility test");
    rust_compat_test_exe_step.dependOn(&run_rust_compat_test_exe.step);

    // Debug compatibility test executable module
    const debug_compat_module = b.createModule(.{
        .root_source_file = b.path("examples/debug_compat.zig"),
        .target = target,
        .optimize = optimize,
    });
    debug_compat_module.addImport("hash-zig", hash_zig_module);

    const debug_compat_exe = b.addExecutable(.{
        .name = "debug-compat",
        .root_module = debug_compat_module,
    });
    b.installArtifact(debug_compat_exe);

    const run_debug_compat_exe = b.addRunArtifact(debug_compat_exe);
    const debug_compat_exe_step = b.step("debug-compat", "Run debug compatibility test");
    debug_compat_exe_step.dependOn(&run_debug_compat_exe.step);

    // Debug native full executable module
    const debug_native_full_module = b.createModule(.{
        .root_source_file = b.path("examples/debug_native_full.zig"),
        .target = target,
        .optimize = optimize,
    });
    debug_native_full_module.addImport("hash-zig", hash_zig_module);

    const debug_native_full_exe = b.addExecutable(.{
        .name = "debug-native-full",
        .root_module = debug_native_full_module,
    });
    b.installArtifact(debug_native_full_exe);

    const run_debug_native_full_exe = b.addRunArtifact(debug_native_full_exe);
    const debug_native_full_exe_step = b.step("debug-native-full", "Full debug output for native implementation");
    debug_native_full_exe_step.dependOn(&run_debug_native_full_exe.step);

    // Test Poseidon2 raw executable module - REMOVED (file doesn't exist)

    // Test parameter generation executable module - REMOVED (file doesn't exist)

    // Quick compat test (lifetime 2^10)
    const quick_compat_module = b.createModule(.{
        .root_source_file = b.path("examples/quick_compat_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    quick_compat_module.addImport("hash-zig", hash_zig_module);

    const quick_compat_exe = b.addExecutable(.{
        .name = "quick-compat-test",
        .root_module = quick_compat_module,
    });
    b.installArtifact(quick_compat_exe);

    const run_quick_compat_exe = b.addRunArtifact(quick_compat_exe);
    const quick_compat_exe_step = b.step("quick-compat", "Quick compatibility test (2^10)");
    quick_compat_exe_step.dependOn(&run_quick_compat_exe.step);

    // Verify P2-24 executable module
    const verify_p2_24_module = b.createModule(.{
        .root_source_file = b.path("examples/verify_p2_24.zig"),
        .target = target,
        .optimize = optimize,
    });
    verify_p2_24_module.addImport("poseidon", poseidon_mod);

    const verify_p2_24_exe = b.addExecutable(.{
        .name = "verify-p2-24",
        .root_module = verify_p2_24_module,
    });
    b.installArtifact(verify_p2_24_exe);

    const run_verify_p2_24_exe = b.addRunArtifact(verify_p2_24_exe);
    const verify_p2_24_exe_step = b.step("verify-p2-24", "Verify Poseidon2-24 against plonky3");
    verify_p2_24_exe_step.dependOn(&run_verify_p2_24_exe.step);

    // Test P2-24 basic executable module - REMOVED (file doesn't exist)

    // Simple debug executable module
    const simple_debug_module = b.createModule(.{
        .root_source_file = b.path("examples/simple_debug.zig"),
        .target = target,
        .optimize = optimize,
    });
    simple_debug_module.addImport("hash-zig", hash_zig_module);

    const simple_debug_exe = b.addExecutable(.{
        .name = "simple-debug",
        .root_module = simple_debug_module,
    });
    b.installArtifact(simple_debug_exe);

    const run_simple_debug_exe = b.addRunArtifact(simple_debug_exe);
    const simple_debug_exe_step = b.step("simple-debug", "Simple debug output for first steps");
    simple_debug_exe_step.dependOn(&run_simple_debug_exe.step);

    // Trace keygen executable module
    const trace_keygen_module = b.createModule(.{
        .root_source_file = b.path("examples/trace_keygen.zig"),
        .target = target,
        .optimize = optimize,
    });
    trace_keygen_module.addImport("hash-zig", hash_zig_module);

    const trace_keygen_exe = b.addExecutable(.{
        .name = "trace-keygen",
        .root_module = trace_keygen_module,
    });
    b.installArtifact(trace_keygen_exe);

    const run_trace_keygen_exe = b.addRunArtifact(trace_keygen_exe);
    const trace_keygen_exe_step = b.step("trace-keygen", "Complete key generation trace");
    trace_keygen_exe_step.dependOn(&run_trace_keygen_exe.step);

    // Test domain separator executable module - REMOVED (file doesn't exist)

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
    // Poseidon2 test files moved to investigations/ directory

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
