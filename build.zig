const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const enable_docs = b.option(bool, "docs", "Enable docs generation") orelse false;
    const enable_debug_logs = b.option(bool, "debug-logs", "Enable verbose std.debug logging") orelse false;

    const build_options = b.addOptions();
    build_options.addOption(bool, "enable_debug_logs", enable_debug_logs);
    const enable_lifetime_2_32 = b.option(bool, "enable-lifetime-2-32", "Enable lifetime 2^32 tests (default: false)") orelse false;
    build_options.addOption(bool, "enable_lifetime_2_32", enable_lifetime_2_32);

    // Create the module
    const hash_zig_module = b.addModule("hash-zig", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    hash_zig_module.addOptions("build_options", build_options);

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

    // Performance tests
    const performance_tests = b.addTest(.{
        .root_source_file = b.path("investigations/test/performance_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    performance_tests.root_module.addImport("hash-zig", hash_zig_module);
    const run_performance_tests = b.addRunArtifact(performance_tests);

    // Rust compatibility tests
    const rust_compat_tests = b.addTest(.{
        .root_source_file = b.path("investigations/test/rust_compatibility_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    rust_compat_tests.root_module.addImport("hash-zig", hash_zig_module);
    const run_rust_compat_tests = b.addRunArtifact(rust_compat_tests);

    // Comprehensive Rust compatibility tests
    const comprehensive_rust_compat_tests = b.addTest(.{
        .root_source_file = b.path("investigations/test/comprehensive_rust_compatibility_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    comprehensive_rust_compat_tests.root_module.addImport("hash-zig", hash_zig_module);
    const run_comprehensive_rust_compat_tests = b.addRunArtifact(comprehensive_rust_compat_tests);

    // Encoding variants tests
    const encoding_variants_tests = b.addTest(.{
        .root_source_file = b.path("investigations/test/encoding_variants_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    encoding_variants_tests.root_module.addImport("hash-zig", hash_zig_module);
    const run_encoding_variants_tests = b.addRunArtifact(encoding_variants_tests);

    // Performance benchmark tests
    const performance_benchmark_tests = b.addTest(.{
        .root_source_file = b.path("investigations/test/performance_benchmark_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    performance_benchmark_tests.root_module.addImport("hash-zig", hash_zig_module);
    const run_performance_benchmark_tests = b.addRunArtifact(performance_benchmark_tests);

    // Lifetime tests (2^8 and 2^18) - always use ReleaseFast for key generation
    const lifetime_tests_options = b.addOptions();
    lifetime_tests_options.addOption(bool, "enable_lifetime_2_32", enable_lifetime_2_32);
    const lifetime_tests = b.addTest(.{
        .root_source_file = b.path("scripts/test_lifetimes.zig"),
        .target = target,
        .optimize = .ReleaseFast,
    });
    lifetime_tests.root_module.addImport("hash-zig", hash_zig_module);
    lifetime_tests.root_module.addOptions("build_options", lifetime_tests_options);
    const run_lifetime_tests = b.addRunArtifact(lifetime_tests);

    // Test step runs all tests
    const test_step = b.step("test", "Run core library tests");
    test_step.dependOn(&run_lib_unit_tests.step);

    const extended_tests_step = b.step("test-extended", "Run extended compatibility and benchmark tests");
    extended_tests_step.dependOn(&run_performance_tests.step);
    extended_tests_step.dependOn(&run_rust_compat_tests.step);
    extended_tests_step.dependOn(&run_comprehensive_rust_compat_tests.step);
    extended_tests_step.dependOn(&run_encoding_variants_tests.step);
    extended_tests_step.dependOn(&run_performance_benchmark_tests.step);

    const lifetime_tests_step = b.step("test-lifetimes", "Run lifetime tests (2^8 and 2^18)");
    lifetime_tests_step.dependOn(&run_lifetime_tests.step);

    // Basic usage example
    const basic_example_module = b.createModule(.{
        .root_source_file = b.path("examples/basic_usage.zig"),
        .target = target,
        .optimize = optimize,
    });
    basic_example_module.addImport("hash-zig", hash_zig_module);

    const basic_example_exe = b.addExecutable(.{
        .name = "basic-example",
        .root_module = basic_example_module,
    });
    b.installArtifact(basic_example_exe);

    const run_basic_example_exe = b.addRunArtifact(basic_example_exe);
    const basic_example_exe_step = b.step("example", "Run basic usage example");
    basic_example_exe_step.dependOn(&run_basic_example_exe.step);

    // Zig benchmark utilities (lifetime 2^8)
    const zig_sign_2_8_module = b.createModule(.{
        .root_source_file = b.path("benchmark/zig_benchmark/src/sign_message.zig"),
        .target = target,
        .optimize = optimize,
    });
    zig_sign_2_8_module.addImport("hash-zig", hash_zig_module);

    const zig_sign_2_8_exe = b.addExecutable(.{
        .name = "zig-sign-message",
        .root_module = zig_sign_2_8_module,
    });
    b.installArtifact(zig_sign_2_8_exe);

    const zig_verify_2_8_module = b.createModule(.{
        .root_source_file = b.path("benchmark/zig_benchmark/src/verify_signature.zig"),
        .target = target,
        .optimize = optimize,
    });
    zig_verify_2_8_module.addImport("hash-zig", hash_zig_module);

    const zig_verify_2_8_exe = b.addExecutable(.{
        .name = "zig-verify-signature",
        .root_module = zig_verify_2_8_module,
    });
    b.installArtifact(zig_verify_2_8_exe);

    // Remote hash tool
    const zig_remote_hash_module = b.createModule(.{
        .root_source_file = b.path("benchmark/zig_benchmark/src/remote_hash_tool.zig"),
        .target = target,
        .optimize = optimize,
    });
    zig_remote_hash_module.addImport("hash-zig", hash_zig_module);

    const zig_remote_hash_exe = b.addExecutable(.{
        .name = "zig-remote-hash-tool",
        .root_module = zig_remote_hash_module,
    });
    b.installArtifact(zig_remote_hash_exe);

    // Cross-language compatibility tool
    const cross_lang_zig_tool_module = b.createModule(.{
        .root_source_file = b.path("benchmark/zig_benchmark/src/cross_lang_zig_tool.zig"),
        .target = target,
        .optimize = optimize,
    });
    cross_lang_zig_tool_module.addImport("hash-zig", hash_zig_module);

    const cross_lang_zig_tool_exe = b.addExecutable(.{
        .name = "cross-lang-zig-tool",
        .root_module = cross_lang_zig_tool_module,
    });
    b.installArtifact(cross_lang_zig_tool_exe);

    // Rust compatibility test step (for CI)
    const rust_test_step = b.step("test-rust-compat", "Run ONLY Rust compatibility tests");
    rust_test_step.dependOn(&run_rust_compat_tests.step);

    // Main GeneralizedXMSS compatibility test executable
    const generalized_xmss_test_module = b.createModule(.{
        .root_source_file = b.path("examples/test_generalized_xmss_compat.zig"),
        .target = target,
        .optimize = optimize,
    });
    generalized_xmss_test_module.addImport("hash-zig", hash_zig_module);

    const generalized_xmss_test_exe = b.addExecutable(.{
        .name = "test-generalized-xmss-compat",
        .root_module = generalized_xmss_test_module,
    });
    b.installArtifact(generalized_xmss_test_exe);

    const run_generalized_xmss_test_exe = b.addRunArtifact(generalized_xmss_test_exe);
    const generalized_xmss_test_exe_step = b.step("test-generalized-xmss-compat", "Run GeneralizedXMSS Rust compatibility test");
    generalized_xmss_test_exe_step.dependOn(&run_generalized_xmss_test_exe.step);

    // ShakePRF compatibility test
    const shake_prf_test_module = b.createModule(.{
        .root_source_file = b.path("examples/test_shake_prf_compatibility.zig"),
        .target = target,
        .optimize = optimize,
    });
    shake_prf_test_module.addImport("hash-zig", hash_zig_module);

    const shake_prf_test_exe = b.addExecutable(.{
        .name = "test-shake-prf-compat",
        .root_module = shake_prf_test_module,
    });
    b.installArtifact(shake_prf_test_exe);

    const run_shake_prf_test_exe = b.addRunArtifact(shake_prf_test_exe);
    const shake_prf_test_exe_step = b.step("test-shake-prf-compat", "Run ShakePRF compatibility test");
    shake_prf_test_exe_step.dependOn(&run_shake_prf_test_exe.step);

    // Poseidon2 compatibility test
    const poseidon2_test_module = b.createModule(.{
        .root_source_file = b.path("examples/test_poseidon2_compatibility.zig"),
        .target = target,
        .optimize = optimize,
    });
    poseidon2_test_module.addImport("hash-zig", hash_zig_module);

    const poseidon2_test_exe = b.addExecutable(.{
        .name = "test-poseidon2-compat",
        .root_module = poseidon2_test_module,
    });
    b.installArtifact(poseidon2_test_exe);

    const run_poseidon2_test_exe = b.addRunArtifact(poseidon2_test_exe);
    const poseidon2_test_exe_step = b.step("test-poseidon2-compat", "Run Poseidon2 compatibility test");
    poseidon2_test_exe_step.dependOn(&run_poseidon2_test_exe.step);

    // Benchmark script
    const benchmark_module = b.createModule(.{
        .root_source_file = b.path("scripts/benchmark.zig"),
        .target = target,
        .optimize = optimize,
    });
    benchmark_module.addImport("hash-zig", hash_zig_module);

    const benchmark_exe = b.addExecutable(.{
        .name = "hash-zig-benchmark",
        .root_module = benchmark_module,
    });
    b.installArtifact(benchmark_exe);

    const run_benchmark_exe = b.addRunArtifact(benchmark_exe);
    const benchmark_exe_step = b.step("benchmark", "Run hash-zig benchmarks");
    benchmark_exe_step.dependOn(&run_benchmark_exe.step);

    // Key generation benchmark script
    const keygen_benchmark_module = b.createModule(.{
        .root_source_file = b.path("scripts/benchmark_keygen.zig"),
        .target = target,
        .optimize = optimize,
    });
    keygen_benchmark_module.addImport("hash-zig", hash_zig_module);

    const keygen_benchmark_exe = b.addExecutable(.{
        .name = "benchmark-keygen",
        .root_module = keygen_benchmark_module,
    });
    b.installArtifact(keygen_benchmark_exe);

    const run_keygen_benchmark_exe = b.addRunArtifact(keygen_benchmark_exe);
    const keygen_benchmark_exe_step = b.step("benchmark-keygen", "Run key generation benchmarks");
    keygen_benchmark_exe_step.dependOn(&run_keygen_benchmark_exe.step);

    // Parallel benchmark
    const parallel_benchmark_module = b.createModule(.{
        .root_source_file = b.path("scripts/benchmark_parallel.zig"),
        .target = target,
        .optimize = optimize,
    });
    parallel_benchmark_module.addImport("hash-zig", hash_zig_module);

    const parallel_benchmark_exe = b.addExecutable(.{
        .name = "benchmark-parallel",
        .root_module = parallel_benchmark_module,
    });
    b.installArtifact(parallel_benchmark_exe);

    const run_parallel_benchmark_exe = b.addRunArtifact(parallel_benchmark_exe);
    const parallel_benchmark_exe_step = b.step("benchmark-parallel", "Run parallel tree generation benchmark");
    parallel_benchmark_exe_step.dependOn(&run_parallel_benchmark_exe.step);

    // Performance profiling
    const profile_module = b.createModule(.{
        .root_source_file = b.path("scripts/profile_keygen_detailed.zig"),
        .target = target,
        .optimize = optimize,
    });
    profile_module.addImport("hash-zig", hash_zig_module);

    const profile_exe = b.addExecutable(.{
        .name = "profile-keygen",
        .root_module = profile_module,
    });
    b.installArtifact(profile_exe);

    const run_profile_exe = b.addRunArtifact(profile_exe);
    const profile_exe_step = b.step("profile-keygen", "Run detailed key generation performance profiling");
    profile_exe_step.dependOn(&run_profile_exe.step);

    // Documentation generation
    if (enable_docs) {
        const docs = b.addInstallDirectory(.{
            .source_dir = lib.getEmittedDocs(),
            .install_dir = .prefix,
            .install_subdir = "docs",
        });
        const docs_step = b.step("docs", "Generate documentation");
        docs_step.dependOn(&docs.step);
    }
}
