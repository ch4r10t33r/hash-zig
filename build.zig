const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const enable_docs = b.option(bool, "docs", "Enable docs generation") orelse false;
    const enable_debug_logs = b.option(bool, "debug-logs", "Enable verbose std.debug logging") orelse false;

    const build_options = b.addOptions();
    build_options.addOption(bool, "enable_debug_logs", enable_debug_logs);

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

    // Test step runs all tests
    const test_step = b.step("test", "Run core library tests");
    test_step.dependOn(&run_lib_unit_tests.step);

    const extended_tests_step = b.step("test-extended", "Run extended compatibility and benchmark tests");
    extended_tests_step.dependOn(&run_performance_tests.step);
    extended_tests_step.dependOn(&run_rust_compat_tests.step);
    extended_tests_step.dependOn(&run_comprehensive_rust_compat_tests.step);
    extended_tests_step.dependOn(&run_encoding_variants_tests.step);
    extended_tests_step.dependOn(&run_performance_benchmark_tests.step);

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

    // Lifetime 2^18 sign/verify investigation
    const lifetime_2_18_module = b.createModule(.{
        .root_source_file = b.path("investigations/test_lifetime_2_18.zig"),
        .target = target,
        .optimize = optimize,
    });
    lifetime_2_18_module.addImport("hash-zig", hash_zig_module);

    const lifetime_2_18_exe = b.addExecutable(.{
        .name = "lifetime-2-18-test",
        .root_module = lifetime_2_18_module,
    });
    b.installArtifact(lifetime_2_18_exe);

    const run_lifetime_2_18_exe = b.addRunArtifact(lifetime_2_18_exe);
    const lifetime_2_18_step = b.step("test-lifetime-2-18", "Run lifetime 2^18 Zig sign/verify test");
    lifetime_2_18_step.dependOn(&run_lifetime_2_18_exe.step);

    // Lifetime 2^18 signing and verification tools
    const sign_lifetime_2_18_module = b.createModule(.{
        .root_source_file = b.path("investigations/sign_lifetime_2_18.zig"),
        .target = target,
        .optimize = optimize,
    });
    sign_lifetime_2_18_module.addImport("root.zig", hash_zig_module);

    const sign_lifetime_2_18_exe = b.addExecutable(.{
        .name = "sign-lifetime-2-18",
        .root_module = sign_lifetime_2_18_module,
    });
    b.installArtifact(sign_lifetime_2_18_exe);

    const verify_lifetime_2_18_module = b.createModule(.{
        .root_source_file = b.path("investigations/verify_lifetime_2_18.zig"),
        .target = target,
        .optimize = optimize,
    });
    verify_lifetime_2_18_module.addImport("root.zig", hash_zig_module);

    const verify_lifetime_2_18_exe = b.addExecutable(.{
        .name = "verify-lifetime-2-18",
        .root_module = verify_lifetime_2_18_module,
    });
    b.installArtifact(verify_lifetime_2_18_exe);

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

    // Investigation programs (moved to investigations/ directory)
    const rust_algorithm_port_module = b.createModule(.{
        .root_source_file = b.path("investigations/rust_algorithm_port.zig"),
        .target = target,
        .optimize = optimize,
    });
    rust_algorithm_port_module.addImport("hash-zig", hash_zig_module);

    const rust_algorithm_port_exe = b.addExecutable(.{
        .name = "rust-algorithm-port",
        .root_module = rust_algorithm_port_module,
    });
    b.installArtifact(rust_algorithm_port_exe);

    const run_rust_algorithm_port_exe = b.addRunArtifact(rust_algorithm_port_exe);
    const rust_algorithm_port_step = b.step("rust-algorithm-port", "Run Rust algorithm port for debugging");
    rust_algorithm_port_step.dependOn(&run_rust_algorithm_port_exe.step);

    // Step-by-step comparison tool
    const step_by_step_comparison_module = b.createModule(.{
        .root_source_file = b.path("investigations/step_by_step_comparison.zig"),
        .target = target,
        .optimize = optimize,
    });
    step_by_step_comparison_module.addImport("hash-zig", hash_zig_module);

    const step_by_step_comparison_exe = b.addExecutable(.{
        .name = "step-by-step-comparison",
        .root_module = step_by_step_comparison_module,
    });
    b.installArtifact(step_by_step_comparison_exe);

    const run_step_by_step_comparison_exe = b.addRunArtifact(step_by_step_comparison_exe);
    const step_by_step_comparison_step = b.step("step-by-step-comparison", "Run step-by-step comparison tool");
    step_by_step_comparison_step.dependOn(&run_step_by_step_comparison_exe.step);

    // Bottom tree roots comparison tool
    const bottom_tree_roots_comparison_module = b.createModule(.{
        .root_source_file = b.path("investigations/bottom_tree_roots_comparison.zig"),
        .target = target,
        .optimize = optimize,
    });
    bottom_tree_roots_comparison_module.addImport("hash-zig", hash_zig_module);

    const bottom_tree_roots_comparison_exe = b.addExecutable(.{
        .name = "bottom-tree-roots-comparison",
        .root_module = bottom_tree_roots_comparison_module,
    });
    b.installArtifact(bottom_tree_roots_comparison_exe);

    const run_bottom_tree_roots_comparison_exe = b.addRunArtifact(bottom_tree_roots_comparison_exe);
    const bottom_tree_roots_comparison_step = b.step("bottom-tree-roots-comparison", "Run bottom tree roots comparison tool");
    bottom_tree_roots_comparison_step.dependOn(&run_bottom_tree_roots_comparison_exe.step);

    // Compare bottom tree roots tool
    const compare_bottom_tree_roots_module = b.createModule(.{
        .root_source_file = b.path("investigations/compare_bottom_tree_roots.zig"),
        .target = target,
        .optimize = optimize,
    });
    compare_bottom_tree_roots_module.addImport("hash-zig", hash_zig_module);

    const compare_bottom_tree_roots_exe = b.addExecutable(.{
        .name = "compare-bottom-tree-roots",
        .root_module = compare_bottom_tree_roots_module,
    });
    b.installArtifact(compare_bottom_tree_roots_exe);

    const run_compare_bottom_tree_roots_exe = b.addRunArtifact(compare_bottom_tree_roots_exe);
    const compare_bottom_tree_roots_step = b.step("compare-bottom-tree-roots", "Run compare bottom tree roots tool");
    compare_bottom_tree_roots_step.dependOn(&run_compare_bottom_tree_roots_exe.step);

    // Compare top tree building tool
    const compare_top_tree_building_module = b.createModule(.{
        .root_source_file = b.path("investigations/compare_top_tree_building.zig"),
        .target = target,
        .optimize = optimize,
    });
    compare_top_tree_building_module.addImport("hash-zig", hash_zig_module);

    const compare_top_tree_building_exe = b.addExecutable(.{
        .name = "compare-top-tree-building",
        .root_module = compare_top_tree_building_module,
    });
    b.installArtifact(compare_top_tree_building_exe);

    const run_compare_top_tree_building_exe = b.addRunArtifact(compare_top_tree_building_exe);
    const compare_top_tree_building_step = b.step("compare-top-tree-building", "Run compare top tree building tool");
    compare_top_tree_building_step.dependOn(&run_compare_top_tree_building_exe.step);

    // Analyze processing order tool
    const analyze_processing_order_module = b.createModule(.{
        .root_source_file = b.path("investigations/analyze_processing_order.zig"),
        .target = target,
        .optimize = optimize,
    });
    analyze_processing_order_module.addImport("hash-zig", hash_zig_module);

    const analyze_processing_order_exe = b.addExecutable(.{
        .name = "analyze-processing-order",
        .root_module = analyze_processing_order_module,
    });
    b.installArtifact(analyze_processing_order_exe);

    const run_analyze_processing_order_exe = b.addRunArtifact(analyze_processing_order_exe);
    const analyze_processing_order_step = b.step("analyze-processing-order", "Run analyze processing order tool");
    analyze_processing_order_step.dependOn(&run_analyze_processing_order_exe.step);

    // Compare RNG consumption tool
    const compare_rng_consumption_module = b.createModule(.{
        .root_source_file = b.path("investigations/compare_rng_consumption.zig"),
        .target = target,
        .optimize = optimize,
    });
    compare_rng_consumption_module.addImport("hash-zig", hash_zig_module);

    const compare_rng_consumption_exe = b.addExecutable(.{
        .name = "compare-rng-consumption",
        .root_module = compare_rng_consumption_module,
    });
    b.installArtifact(compare_rng_consumption_exe);

    const run_compare_rng_consumption_exe = b.addRunArtifact(compare_rng_consumption_exe);
    const compare_rng_consumption_step = b.step("compare-rng-consumption", "Run compare RNG consumption tool");
    compare_rng_consumption_step.dependOn(&run_compare_rng_consumption_exe.step);

    // Deep algorithm analysis tool
    const deep_algorithm_analysis_module = b.createModule(.{
        .root_source_file = b.path("investigations/deep_algorithm_analysis.zig"),
        .target = target,
        .optimize = optimize,
    });
    deep_algorithm_analysis_module.addImport("hash-zig", hash_zig_module);

    const deep_algorithm_analysis_exe = b.addExecutable(.{
        .name = "deep-algorithm-analysis",
        .root_module = deep_algorithm_analysis_module,
    });
    b.installArtifact(deep_algorithm_analysis_exe);

    const run_deep_algorithm_analysis_exe = b.addRunArtifact(deep_algorithm_analysis_exe);
    const deep_algorithm_analysis_step = b.step("deep-algorithm-analysis", "Run deep algorithm analysis tool");
    deep_algorithm_analysis_step.dependOn(&run_deep_algorithm_analysis_exe.step);

    // Processing order analysis tool
    const processing_order_analysis_module = b.createModule(.{
        .root_source_file = b.path("investigations/processing_order_analysis.zig"),
        .target = target,
        .optimize = optimize,
    });
    processing_order_analysis_module.addImport("hash-zig", hash_zig_module);

    const processing_order_analysis_exe = b.addExecutable(.{
        .name = "processing-order-analysis",
        .root_module = processing_order_analysis_module,
    });
    b.installArtifact(processing_order_analysis_exe);

    const run_processing_order_analysis_exe = b.addRunArtifact(processing_order_analysis_exe);
    const processing_order_analysis_step = b.step("processing-order-analysis", "Run processing order analysis tool");
    processing_order_analysis_step.dependOn(&run_processing_order_analysis_exe.step);

    // Deep processing order analysis tool
    const processing_order_deep_analysis_module = b.createModule(.{
        .root_source_file = b.path("investigations/processing_order_deep_analysis.zig"),
        .target = target,
        .optimize = optimize,
    });
    processing_order_deep_analysis_module.addImport("hash-zig", hash_zig_module);

    const processing_order_deep_analysis_exe = b.addExecutable(.{
        .name = "processing-order-deep-analysis",
        .root_module = processing_order_deep_analysis_module,
    });
    b.installArtifact(processing_order_deep_analysis_exe);

    const run_processing_order_deep_analysis_exe = b.addRunArtifact(processing_order_deep_analysis_exe);
    const processing_order_deep_analysis_step = b.step("processing-order-deep-analysis", "Run deep processing order analysis tool");
    processing_order_deep_analysis_step.dependOn(&run_processing_order_deep_analysis_exe.step);

    // Focused processing order analysis tool
    const processing_order_focused_analysis_module = b.createModule(.{
        .root_source_file = b.path("investigations/processing_order_focused_analysis.zig"),
        .target = target,
        .optimize = optimize,
    });
    processing_order_focused_analysis_module.addImport("hash-zig", hash_zig_module);

    const processing_order_focused_analysis_exe = b.addExecutable(.{
        .name = "processing-order-focused-analysis",
        .root_module = processing_order_focused_analysis_module,
    });
    b.installArtifact(processing_order_focused_analysis_exe);

    const run_processing_order_focused_analysis_exe = b.addRunArtifact(processing_order_focused_analysis_exe);
    const processing_order_focused_analysis_step = b.step("processing-order-focused-analysis", "Run focused processing order analysis tool");
    processing_order_focused_analysis_step.dependOn(&run_processing_order_focused_analysis_exe.step);

    // Hash function input structure analysis tool
    const hash_function_input_analysis_module = b.createModule(.{
        .root_source_file = b.path("investigations/hash_function_input_analysis.zig"),
        .target = target,
        .optimize = optimize,
    });
    hash_function_input_analysis_module.addImport("hash-zig", hash_zig_module);

    const hash_function_input_analysis_exe = b.addExecutable(.{
        .name = "hash-function-input-analysis",
        .root_module = hash_function_input_analysis_module,
    });
    b.installArtifact(hash_function_input_analysis_exe);

    const run_hash_function_input_analysis_exe = b.addRunArtifact(hash_function_input_analysis_exe);
    const hash_function_input_analysis_step = b.step("hash-function-input-analysis", "Run hash function input structure analysis tool");
    hash_function_input_analysis_step.dependOn(&run_hash_function_input_analysis_exe.step);

    // RNG state synchronization analysis tool
    const rng_state_synchronization_analysis_module = b.createModule(.{
        .root_source_file = b.path("investigations/rng_state_synchronization_analysis.zig"),
        .target = target,
        .optimize = optimize,
    });
    rng_state_synchronization_analysis_module.addImport("hash-zig", hash_zig_module);

    const rng_state_synchronization_analysis_exe = b.addExecutable(.{
        .name = "rng-state-synchronization-analysis",
        .root_module = rng_state_synchronization_analysis_module,
    });
    b.installArtifact(rng_state_synchronization_analysis_exe);

    const run_rng_state_synchronization_analysis_exe = b.addRunArtifact(rng_state_synchronization_analysis_exe);
    const rng_state_synchronization_analysis_step = b.step("rng-state-synchronization-analysis", "Run RNG state synchronization analysis tool");
    rng_state_synchronization_analysis_step.dependOn(&run_rng_state_synchronization_analysis_exe.step);

    // Hash function application analysis tool
    const hash_function_application_analysis_module = b.createModule(.{
        .root_source_file = b.path("investigations/hash_function_application_analysis.zig"),
        .target = target,
        .optimize = optimize,
    });
    hash_function_application_analysis_module.addImport("hash-zig", hash_zig_module);

    const hash_function_application_analysis_exe = b.addExecutable(.{
        .name = "hash-function-application-analysis",
        .root_module = hash_function_application_analysis_module,
    });
    b.installArtifact(hash_function_application_analysis_exe);

    const run_hash_function_application_analysis_exe = b.addRunArtifact(hash_function_application_analysis_exe);
    const hash_function_application_analysis_step = b.step("hash-function-application-analysis", "Run hash function application analysis tool");
    hash_function_application_analysis_step.dependOn(&run_hash_function_application_analysis_exe.step);

    // Field element conversion analysis tool
    const field_element_conversion_analysis_module = b.createModule(.{
        .root_source_file = b.path("investigations/field_element_conversion_analysis.zig"),
        .target = target,
        .optimize = optimize,
    });
    field_element_conversion_analysis_module.addImport("hash-zig", hash_zig_module);

    const field_element_conversion_analysis_exe = b.addExecutable(.{
        .name = "field-element-conversion-analysis",
        .root_module = field_element_conversion_analysis_module,
    });
    b.installArtifact(field_element_conversion_analysis_exe);

    const run_field_element_conversion_analysis_exe = b.addRunArtifact(field_element_conversion_analysis_exe);
    const field_element_conversion_analysis_step = b.step("field-element-conversion-analysis", "Run field element conversion analysis tool");
    field_element_conversion_analysis_step.dependOn(&run_field_element_conversion_analysis_exe.step);

    // Investigation step runs key investigation programs
    const investigation_step = b.step("investigate", "Run key investigation programs");
    investigation_step.dependOn(&run_rust_algorithm_port_exe.step);
    investigation_step.dependOn(&run_step_by_step_comparison_exe.step);
    investigation_step.dependOn(&run_bottom_tree_roots_comparison_exe.step);
    investigation_step.dependOn(&run_compare_bottom_tree_roots_exe.step);
    investigation_step.dependOn(&run_compare_top_tree_building_exe.step);
    investigation_step.dependOn(&run_analyze_processing_order_exe.step);
    investigation_step.dependOn(&run_compare_rng_consumption_exe.step);
    investigation_step.dependOn(&run_deep_algorithm_analysis_exe.step);
    investigation_step.dependOn(&run_processing_order_analysis_exe.step);
    investigation_step.dependOn(&run_processing_order_deep_analysis_exe.step);
    investigation_step.dependOn(&run_processing_order_focused_analysis_exe.step);
    investigation_step.dependOn(&run_hash_function_input_analysis_exe.step);
    investigation_step.dependOn(&run_rng_state_synchronization_analysis_exe.step);
    investigation_step.dependOn(&run_hash_function_application_analysis_exe.step);
    investigation_step.dependOn(&run_field_element_conversion_analysis_exe.step);

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
