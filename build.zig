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
        // Always run compat test in ReleaseFast
        .optimize = .ReleaseFast,
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

    // Debug version of rust compatibility test
    const rust_compat_test_debug_module = b.createModule(.{
        .root_source_file = b.path("examples/rust_compat_test.zig"),
        .target = target,
        .optimize = .Debug, // Debug mode for better error traces
    });
    rust_compat_test_debug_module.addImport("hash-zig", hash_zig_module);

    const rust_compat_test_debug_exe = b.addExecutable(.{
        .name = "rust-compat-test-debug",
        .root_module = rust_compat_test_debug_module,
    });
    b.installArtifact(rust_compat_test_debug_exe);

    const run_rust_compat_test_debug_exe = b.addRunArtifact(rust_compat_test_debug_exe);
    const rust_compat_test_debug_exe_step = b.step("rust-compat-test-debug", "Run Rust cross-implementation compatibility test in debug mode");
    rust_compat_test_debug_exe_step.dependOn(&run_rust_compat_test_debug_exe.step);

    // Test lifetime 2^3 (8 signatures) - matches Rust PR #91
    const test_lifetime_2_3_module = b.createModule(.{
        .root_source_file = b.path("examples/test_lifetime_2_3.zig"),
        .target = target,
        .optimize = optimize,
    });
    test_lifetime_2_3_module.addImport("hash-zig", hash_zig_module);

    const test_lifetime_2_3_exe = b.addExecutable(.{
        .name = "test-lifetime-2-3",
        .root_module = test_lifetime_2_3_module,
    });
    b.installArtifact(test_lifetime_2_3_exe);

    const run_test_lifetime_2_3_exe = b.addRunArtifact(test_lifetime_2_3_exe);
    const test_lifetime_2_3_exe_step = b.step("test-lifetime-2-3", "Test lifetime 2^3 (8 signatures) - matches Rust PR #91");
    test_lifetime_2_3_exe_step.dependOn(&run_test_lifetime_2_3_exe.step);

    // Rust compatibility test for lifetime 2^3 (8 signatures)
    const rust_compat_test_2_3_module = b.createModule(.{
        .root_source_file = b.path("examples/rust_compat_test_2_3.zig"),
        .target = target,
        .optimize = .ReleaseFast, // Always run in ReleaseFast
    });
    rust_compat_test_2_3_module.addImport("hash-zig", hash_zig_module);

    const rust_compat_test_2_3_exe = b.addExecutable(.{
        .name = "rust-compat-test-2-3",
        .root_module = rust_compat_test_2_3_module,
    });
    b.installArtifact(rust_compat_test_2_3_exe);

    const run_rust_compat_test_2_3_exe = b.addRunArtifact(rust_compat_test_2_3_exe);
    const rust_compat_test_2_3_exe_step = b.step("rust-compat-test-2-3", "Run Rust compatibility test for lifetime 2^3 (8 signatures)");
    rust_compat_test_2_3_exe_step.dependOn(&run_rust_compat_test_2_3_exe.step);

    // Rust compatibility test for lifetime 2^8 (256 signatures)
    const rust_compat_test_2_8_module = b.createModule(.{
        .root_source_file = b.path("examples/rust_compat_test_2_8.zig"),
        .target = target,
        .optimize = .ReleaseFast, // Always run in ReleaseFast
    });
    rust_compat_test_2_8_module.addImport("hash-zig", hash_zig_module);

    const rust_compat_test_2_8_exe = b.addExecutable(.{
        .name = "rust-compat-test-2-8",
        .root_module = rust_compat_test_2_8_module,
    });
    b.installArtifact(rust_compat_test_2_8_exe);

    const run_rust_compat_test_2_8_exe = b.addRunArtifact(rust_compat_test_2_8_exe);
    const rust_compat_test_2_8_exe_step = b.step("rust-compat-test-2-8", "Run Rust compatibility test for lifetime 2^8 (256 signatures)");
    rust_compat_test_2_8_exe_step.dependOn(&run_rust_compat_test_2_8_exe.step);

    // Rust compatibility test for lifetime 2^8 MATCHED (2^18 tree with 256 active epochs)
    const rust_compat_test_2_8_matched_module = b.createModule(.{
        .root_source_file = b.path("examples/rust_compat_test_2_8_matched.zig"),
        .target = target,
        .optimize = .ReleaseFast, // Always run in ReleaseFast
    });
    rust_compat_test_2_8_matched_module.addImport("hash-zig", hash_zig_module);

    const rust_compat_test_2_8_matched_exe = b.addExecutable(.{
        .name = "rust-compat-test-2-8-matched",
        .root_module = rust_compat_test_2_8_matched_module,
    });
    b.installArtifact(rust_compat_test_2_8_matched_exe);

    const run_rust_compat_test_2_8_matched_exe = b.addRunArtifact(rust_compat_test_2_8_matched_exe);
    const rust_compat_test_2_8_matched_exe_step = b.step("rust-compat-test-2-8-matched", "Run Rust compatibility test for lifetime 2^8 MATCHED (2^18 tree with 256 active epochs)");
    rust_compat_test_2_8_matched_exe_step.dependOn(&run_rust_compat_test_2_8_matched_exe.step);

    // Debug Zig parameters
    const debug_zig_parameters_module = b.createModule(.{
        .root_source_file = b.path("examples/debug_zig_parameters.zig"),
        .target = target,
        .optimize = .ReleaseFast,
    });
    debug_zig_parameters_module.addImport("hash-zig", hash_zig_module);

    const debug_zig_parameters_exe = b.addExecutable(.{
        .name = "debug-zig-parameters",
        .root_module = debug_zig_parameters_module,
    });
    b.installArtifact(debug_zig_parameters_exe);

    const run_debug_zig_parameters_exe = b.addRunArtifact(debug_zig_parameters_exe);
    const debug_zig_parameters_exe_step = b.step("debug-zig-parameters", "Debug Zig parameters for lifetime_2_8");
    debug_zig_parameters_exe_step.dependOn(&run_debug_zig_parameters_exe.step);

    // Test parameter alignment
    const test_parameter_alignment_module = b.createModule(.{
        .root_source_file = b.path("examples/test_parameter_alignment.zig"),
        .target = target,
        .optimize = .ReleaseFast,
    });
    test_parameter_alignment_module.addImport("hash-zig", hash_zig_module);

    const test_parameter_alignment_exe = b.addExecutable(.{
        .name = "test-parameter-alignment",
        .root_module = test_parameter_alignment_module,
    });
    b.installArtifact(test_parameter_alignment_exe);

    const run_test_parameter_alignment_exe = b.addRunArtifact(test_parameter_alignment_exe);
    const test_parameter_alignment_exe_step = b.step("test-parameter-alignment", "Test parameter alignment between Rust and Zig");
    test_parameter_alignment_exe_step.dependOn(&run_test_parameter_alignment_exe.step);

    // Test Rust-compatible Zig implementation
    const test_rust_compatible_zig_module = b.createModule(.{
        .root_source_file = b.path("examples/test_rust_compatible_zig.zig"),
        .target = target,
        .optimize = .ReleaseFast,
    });
    test_rust_compatible_zig_module.addImport("hash-zig", hash_zig_module);

    const test_rust_compatible_zig_exe = b.addExecutable(.{
        .name = "test-rust-compatible-zig",
        .root_module = test_rust_compatible_zig_module,
    });
    b.installArtifact(test_rust_compatible_zig_exe);

    const run_test_rust_compatible_zig_exe = b.addRunArtifact(test_rust_compatible_zig_exe);
    const test_rust_compatible_zig_exe_step = b.step("test-rust-compatible-zig", "Test Rust-compatible Zig implementation");
    test_rust_compatible_zig_exe_step.dependOn(&run_test_rust_compatible_zig_exe.step);

    // Test Rust-compatible integration
    const test_rust_compat_integration_module = b.createModule(.{
        .root_source_file = b.path("examples/test_rust_compat_integration.zig"),
        .target = target,
        .optimize = .ReleaseFast,
    });
    test_rust_compat_integration_module.addImport("hash-zig", hash_zig_module);

    const test_rust_compat_integration_exe = b.addExecutable(.{
        .name = "test-rust-compat-integration",
        .root_module = test_rust_compat_integration_module,
    });
    b.installArtifact(test_rust_compat_integration_exe);

    const run_test_rust_compat_integration_exe = b.addRunArtifact(test_rust_compat_integration_exe);
    const test_rust_compat_integration_exe_step = b.step("test-rust-compat-integration", "Test Rust-compatible integration");
    test_rust_compat_integration_exe_step.dependOn(&run_test_rust_compat_integration_exe.step);

    // Final compatibility test
    const test_final_compatibility_module = b.createModule(.{
        .root_source_file = b.path("examples/test_final_compatibility.zig"),
        .target = target,
        .optimize = .ReleaseFast,
    });
    test_final_compatibility_module.addImport("hash-zig", hash_zig_module);

    const test_final_compatibility_exe = b.addExecutable(.{
        .name = "test-final-compatibility",
        .root_module = test_final_compatibility_module,
    });
    b.installArtifact(test_final_compatibility_exe);

    const run_test_final_compatibility_exe = b.addRunArtifact(test_final_compatibility_exe);
    const test_final_compatibility_exe_step = b.step("test-final-compatibility", "Final compatibility test between Rust and Zig");
    test_final_compatibility_exe_step.dependOn(&run_test_final_compatibility_exe.step);

    // Test all Rust-compatible lifetimes
    const test_all_rust_compat_lifetimes_module = b.createModule(.{
        .root_source_file = b.path("examples/test_all_rust_compat_lifetimes.zig"),
        .target = target,
        .optimize = .ReleaseFast,
    });
    test_all_rust_compat_lifetimes_module.addImport("hash-zig", hash_zig_module);

    const test_all_rust_compat_lifetimes_exe = b.addExecutable(.{
        .name = "test-all-rust-compat-lifetimes",
        .root_module = test_all_rust_compat_lifetimes_module,
    });
    b.installArtifact(test_all_rust_compat_lifetimes_exe);

    const run_test_all_rust_compat_lifetimes_exe = b.addRunArtifact(test_all_rust_compat_lifetimes_exe);
    const test_all_rust_compat_lifetimes_exe_step = b.step("test-all-rust-compat-lifetimes", "Test all Rust-compatible lifetimes and functionality");
    test_all_rust_compat_lifetimes_exe_step.dependOn(&run_test_all_rust_compat_lifetimes_exe.step);

    // Test full Rust compatibility
    const test_full_rust_compatibility_module = b.createModule(.{
        .root_source_file = b.path("examples/test_full_rust_compatibility.zig"),
        .target = target,
        .optimize = .ReleaseFast,
    });
    test_full_rust_compatibility_module.addImport("hash-zig", hash_zig_module);

    const test_full_rust_compatibility_exe = b.addExecutable(.{
        .name = "test-full-rust-compatibility",
        .root_module = test_full_rust_compatibility_module,
    });
    b.installArtifact(test_full_rust_compatibility_exe);

    const run_test_full_rust_compatibility_exe = b.addRunArtifact(test_full_rust_compatibility_exe);
    const test_full_rust_compatibility_exe_step = b.step("test-full-rust-compatibility", "Test full Rust compatibility with all components");
    test_full_rust_compatibility_exe_step.dependOn(&run_test_full_rust_compatibility_exe.step);

    // Test Rust-compatible key generation
    const test_rust_compat_keygen_module = b.createModule(.{
        .root_source_file = b.path("examples/test_rust_compat_keygen.zig"),
        .target = target,
        .optimize = .ReleaseFast,
    });
    test_rust_compat_keygen_module.addImport("hash-zig", hash_zig_module);

    const test_rust_compat_keygen_exe = b.addExecutable(.{
        .name = "test-rust-compat-keygen",
        .root_module = test_rust_compat_keygen_module,
    });
    b.installArtifact(test_rust_compat_keygen_exe);

    const run_test_rust_compat_keygen_exe = b.addRunArtifact(test_rust_compat_keygen_exe);
    const test_rust_compat_keygen_exe_step = b.step("test-rust-compat-keygen", "Test Rust-compatible key generation");
    test_rust_compat_keygen_exe_step.dependOn(&run_test_rust_compat_keygen_exe.step);

    // Test simplified Rust compatibility
    const test_rust_compat_simple_module = b.createModule(.{
        .root_source_file = b.path("examples/test_rust_compat_simple.zig"),
        .target = target,
        .optimize = .ReleaseFast,
    });
    test_rust_compat_simple_module.addImport("hash-zig", hash_zig_module);

    const test_rust_compat_simple_exe = b.addExecutable(.{
        .name = "test-rust-compat-simple",
        .root_module = test_rust_compat_simple_module,
    });
    b.installArtifact(test_rust_compat_simple_exe);

    const run_test_rust_compat_simple_exe = b.addRunArtifact(test_rust_compat_simple_exe);
    const test_rust_compat_simple_exe_step = b.step("test-rust-compat-simple", "Test simplified Rust compatibility");
    test_rust_compat_simple_exe_step.dependOn(&run_test_rust_compat_simple_exe.step);

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

    // Simple compatibility test executable module
    const simple_compat_module = b.createModule(.{
        .root_source_file = b.path("examples/simple_compat_test.zig"),
        .target = target,
        // Always run compat test in ReleaseFast
        .optimize = .ReleaseFast,
    });
    simple_compat_module.addImport("hash-zig", hash_zig_module);

    const simple_compat_exe = b.addExecutable(.{
        .name = "simple-compat-test",
        .root_module = simple_compat_module,
    });
    b.installArtifact(simple_compat_exe);

    const run_simple_compat_exe = b.addRunArtifact(simple_compat_exe);
    const simple_compat_exe_step = b.step("simple-compat-test", "Run simple compatibility test (2^10)");
    simple_compat_exe_step.dependOn(&run_simple_compat_exe.step);

    // Minimal test executable module
    const minimal_module = b.createModule(.{
        .root_source_file = b.path("examples/minimal_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    minimal_module.addImport("hash-zig", hash_zig_module);

    const minimal_exe = b.addExecutable(.{
        .name = "minimal-test",
        .root_module = minimal_module,
    });
    b.installArtifact(minimal_exe);

    const run_minimal_exe = b.addRunArtifact(minimal_exe);
    const minimal_exe_step = b.step("minimal-test", "Run minimal test (2^4)");
    minimal_exe_step.dependOn(&run_minimal_exe.step);

    // Poseidon validation test executable module
    const poseidon_validation_module = b.createModule(.{
        .root_source_file = b.path("examples/poseidon_validation_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    poseidon_validation_module.addImport("hash-zig", hash_zig_module);

    const poseidon_validation_exe = b.addExecutable(.{
        .name = "poseidon-validation-test",
        .root_module = poseidon_validation_module,
    });
    b.installArtifact(poseidon_validation_exe);

    const run_poseidon_validation_exe = b.addRunArtifact(poseidon_validation_exe);
    const poseidon_validation_exe_step = b.step("poseidon-validation-test", "Run Poseidon2 validation test");
    poseidon_validation_exe_step.dependOn(&run_poseidon_validation_exe.step);

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
        // Always run compat test in ReleaseFast
        .optimize = .ReleaseFast,
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

    // Test ShakePRFtoF compatibility executable module
    const test_shake_prf_compat_module = b.createModule(.{
        .root_source_file = b.path("examples/test_shake_prf_compatibility.zig"),
        .target = target,
        .optimize = optimize,
    });
    test_shake_prf_compat_module.addImport("hash-zig", hash_zig_module);

    const test_shake_prf_compat_exe = b.addExecutable(.{
        .name = "test-shake-prf-compat",
        .root_module = test_shake_prf_compat_module,
    });
    b.installArtifact(test_shake_prf_compat_exe);

    const run_test_shake_prf_compat_exe = b.addRunArtifact(test_shake_prf_compat_exe);
    const test_shake_prf_compat_exe_step = b.step("test-shake-prf-compat", "Test ShakePRFtoF compatibility with Rust");
    test_shake_prf_compat_exe_step.dependOn(&run_test_shake_prf_compat_exe.step);

    // Test Poseidon2 compatibility executable module
    const test_poseidon2_compat_module = b.createModule(.{
        .root_source_file = b.path("examples/test_poseidon2_compatibility.zig"),
        .target = target,
        .optimize = optimize,
    });
    test_poseidon2_compat_module.addImport("hash-zig", hash_zig_module);

    const test_poseidon2_compat_exe = b.addExecutable(.{
        .name = "test-poseidon2-compat",
        .root_module = test_poseidon2_compat_module,
    });
    b.installArtifact(test_poseidon2_compat_exe);

    const run_test_poseidon2_compat_exe = b.addRunArtifact(test_poseidon2_compat_exe);
    const test_poseidon2_compat_exe_step = b.step("test-poseidon2-compat", "Test Poseidon2 compatibility with Rust implementation");
    test_poseidon2_compat_exe_step.dependOn(&run_test_poseidon2_compat_exe.step);

    // Test full compatibility for lifetime 2^8 executable module
    const test_full_compat_2_8_module = b.createModule(.{
        .root_source_file = b.path("examples/test_full_compatibility_2_8.zig"),
        .target = target,
        .optimize = optimize,
    });
    test_full_compat_2_8_module.addImport("hash-zig", hash_zig_module);

    const test_full_compat_2_8_exe = b.addExecutable(.{
        .name = "test-full-compat-2-8",
        .root_module = test_full_compat_2_8_module,
    });
    b.installArtifact(test_full_compat_2_8_exe);

    const run_test_full_compat_2_8_exe = b.addRunArtifact(test_full_compat_2_8_exe);
    const test_full_compat_2_8_exe_step = b.step("test-full-compat-2-8", "Test full compatibility for lifetime 2^8 between Rust and Zig");
    test_full_compat_2_8_exe_step.dependOn(&run_test_full_compat_2_8_exe.step);

    // Test simple compatibility for lifetime 2^8 executable module
    const test_simple_compat_2_8_module = b.createModule(.{
        .root_source_file = b.path("examples/test_simple_compatibility_2_8.zig"),
        .target = target,
        .optimize = optimize,
    });
    test_simple_compat_2_8_module.addImport("hash-zig", hash_zig_module);

    const test_simple_compat_2_8_exe = b.addExecutable(.{
        .name = "test-simple-compat-2-8",
        .root_module = test_simple_compat_2_8_module,
    });
    b.installArtifact(test_simple_compat_2_8_exe);

    const run_test_simple_compat_2_8_exe = b.addRunArtifact(test_simple_compat_2_8_exe);
    const test_simple_compat_2_8_exe_step = b.step("test-simple-compat-2-8", "Test simple compatibility for lifetime 2^8");
    test_simple_compat_2_8_exe_step.dependOn(&run_test_simple_compat_2_8_exe.step);

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
