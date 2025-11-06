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

    // Add debug_rng_consumption binary
    const debug_rng_exe = b.addExecutable(.{
        .name = "debug_rng_consumption",
        .root_source_file = b.path("src/debug_rng_consumption.zig"),
        .target = target,
        .optimize = optimize,
    });
    debug_rng_exe.root_module.addImport("hash-zig", hash_zig_module);
    b.installArtifact(debug_rng_exe);

    // Add debug_complete_public_key binary
    const debug_complete_pk_exe = b.addExecutable(.{
        .name = "debug_complete_public_key",
        .root_source_file = b.path("src/debug_complete_public_key.zig"),
        .target = target,
        .optimize = optimize,
    });
    debug_complete_pk_exe.root_module.addImport("hash-zig", hash_zig_module);
    b.installArtifact(debug_complete_pk_exe);

    // Add debug_bottom_tree_detailed binary
    const debug_bottom_tree_exe = b.addExecutable(.{
        .name = "debug_bottom_tree_detailed",
        .root_source_file = b.path("src/debug_bottom_tree_detailed.zig"),
        .target = target,
        .optimize = optimize,
    });
    debug_bottom_tree_exe.root_module.addImport("hash-zig", hash_zig_module);
    b.installArtifact(debug_bottom_tree_exe);

    // Add debug_chain_computation binary
    const debug_chain_exe = b.addExecutable(.{
        .name = "debug_chain_computation",
        .root_source_file = b.path("src/debug_chain_computation.zig"),
        .target = target,
        .optimize = optimize,
    });
    debug_chain_exe.root_module.addImport("hash-zig", hash_zig_module);
    b.installArtifact(debug_chain_exe);

    // Add debug_rng_consumption_tree binary
    const debug_rng_tree_exe = b.addExecutable(.{
        .name = "debug_rng_consumption_tree",
        .root_source_file = b.path("src/debug_rng_consumption_tree.zig"),
        .target = target,
        .optimize = optimize,
    });
    debug_rng_tree_exe.root_module.addImport("hash-zig", hash_zig_module);
    b.installArtifact(debug_rng_tree_exe);

    // Add debug_internal_rng binary
    const debug_internal_rng_exe = b.addExecutable(.{
        .name = "debug_internal_rng",
        .root_source_file = b.path("src/debug_internal_rng.zig"),
        .target = target,
        .optimize = optimize,
    });
    debug_internal_rng_exe.root_module.addImport("hash-zig", hash_zig_module);
    b.installArtifact(debug_internal_rng_exe);

    // Add debug_rng_consumption_detailed binary
    const debug_rng_detailed_exe = b.addExecutable(.{
        .name = "debug_rng_consumption_detailed",
        .root_source_file = b.path("src/debug_rng_consumption_detailed.zig"),
        .target = target,
        .optimize = optimize,
    });
    debug_rng_detailed_exe.root_module.addImport("hash-zig", hash_zig_module);
    b.installArtifact(debug_rng_detailed_exe);

    // Add debug_tree_building_step_by_step binary
    const debug_tree_step_exe = b.addExecutable(.{
        .name = "debug_tree_building_step_by_step",
        .root_source_file = b.path("src/debug_tree_building_step_by_step.zig"),
        .target = target,
        .optimize = optimize,
    });
    debug_tree_step_exe.root_module.addImport("hash-zig", hash_zig_module);
    b.installArtifact(debug_tree_step_exe);

    // Add debug_tree_construction_detailed binary
    const debug_tree_construction_exe = b.addExecutable(.{
        .name = "debug_tree_construction_detailed",
        .root_source_file = b.path("src/debug_tree_construction_detailed.zig"),
        .target = target,
        .optimize = optimize,
    });
    debug_tree_construction_exe.root_module.addImport("hash-zig", hash_zig_module);
    b.installArtifact(debug_tree_construction_exe);

    // Add debug_tweak_computation binary
    const debug_tweak_exe = b.addExecutable(.{
        .name = "debug_tweak_computation",
        .root_source_file = b.path("src/debug_tweak_computation.zig"),
        .target = target,
        .optimize = optimize,
    });
    debug_tweak_exe.root_module.addImport("hash-zig", hash_zig_module);
    b.installArtifact(debug_tweak_exe);

    // Add debug_poseidon2_tree_hash binary
    const debug_poseidon2_tree_exe = b.addExecutable(.{
        .name = "debug_poseidon2_tree_hash",
        .root_source_file = b.path("src/debug_poseidon2_tree_hash.zig"),
        .target = target,
        .optimize = optimize,
    });
    debug_poseidon2_tree_exe.root_module.addImport("hash-zig", hash_zig_module);
    b.installArtifact(debug_poseidon2_tree_exe);

    // Add debug_poseidon2_input_analysis binary
    const debug_poseidon2_input_exe = b.addExecutable(.{
        .name = "debug_poseidon2_input_analysis",
        .root_source_file = b.path("src/debug_poseidon2_input_analysis.zig"),
        .target = target,
        .optimize = optimize,
    });
    debug_poseidon2_input_exe.root_module.addImport("hash-zig", hash_zig_module);
    b.installArtifact(debug_poseidon2_input_exe);

    // Add debug_poseidon2_step_by_step binary
    const debug_poseidon2_step_exe = b.addExecutable(.{
        .name = "debug_poseidon2_step_by_step",
        .root_source_file = b.path("src/debug_poseidon2_step_by_step.zig"),
        .target = target,
        .optimize = optimize,
    });
    debug_poseidon2_step_exe.root_module.addImport("hash-zig", hash_zig_module);
    b.installArtifact(debug_poseidon2_step_exe);

    // Add debug_tweak_levels binary
    const debug_tweak_levels_exe = b.addExecutable(.{
        .name = "debug_tweak_levels",
        .root_source_file = b.path("src/debug_tweak_levels.zig"),
        .target = target,
        .optimize = optimize,
    });
    debug_tweak_levels_exe.root_module.addImport("hash-zig", hash_zig_module);
    b.installArtifact(debug_tweak_levels_exe);

    // Add debug_poseidon2_isolated binary
    const debug_poseidon2_isolated_exe = b.addExecutable(.{
        .name = "debug_poseidon2_isolated",
        .root_source_file = b.path("src/debug_poseidon2_isolated.zig"),
        .target = target,
        .optimize = optimize,
    });
    debug_poseidon2_isolated_exe.root_module.addImport("hash-zig", hash_zig_module);
    b.installArtifact(debug_poseidon2_isolated_exe);

    // Add debug_poseidon2_field_arithmetic binary
    const debug_poseidon2_field_exe = b.addExecutable(.{
        .name = "debug_poseidon2_field_arithmetic",
        .root_source_file = b.path("src/debug_poseidon2_field_arithmetic.zig"),
        .target = target,
        .optimize = optimize,
    });
    debug_poseidon2_field_exe.root_module.addImport("hash-zig", hash_zig_module);
    b.installArtifact(debug_poseidon2_field_exe);

    // Add debug_field_operations binary
    const debug_field_ops_exe = b.addExecutable(.{
        .name = "debug_field_operations",
        .root_source_file = b.path("src/debug_field_operations.zig"),
        .target = target,
        .optimize = optimize,
    });
    debug_field_ops_exe.root_module.addImport("hash-zig", hash_zig_module);
    b.installArtifact(debug_field_ops_exe);

    // Add debug_poseidon2_components binary
    const debug_poseidon2_components_exe = b.addExecutable(.{
        .name = "debug_poseidon2_components",
        .root_source_file = b.path("src/debug_poseidon2_components.zig"),
        .target = target,
        .optimize = optimize,
    });
    debug_poseidon2_components_exe.root_module.addImport("hash-zig", hash_zig_module);
    b.installArtifact(debug_poseidon2_components_exe);

    // Add debug_poseidon2_step_by_step_algorithm binary
    const debug_poseidon2_step_algorithm_exe = b.addExecutable(.{
        .name = "debug_poseidon2_step_by_step_algorithm",
        .root_source_file = b.path("src/debug_poseidon2_step_by_step_algorithm.zig"),
        .target = target,
        .optimize = optimize,
    });
    debug_poseidon2_step_algorithm_exe.root_module.addImport("hash-zig", hash_zig_module);
    b.installArtifact(debug_poseidon2_step_algorithm_exe);

    // Add debug_poseidon2_direct_implementation binary
    const debug_poseidon2_direct_exe = b.addExecutable(.{
        .name = "debug_poseidon2_direct_implementation",
        .root_source_file = b.path("src/debug_poseidon2_direct_implementation.zig"),
        .target = target,
        .optimize = optimize,
    });
    debug_poseidon2_direct_exe.root_module.addImport("hash-zig", hash_zig_module);
    b.installArtifact(debug_poseidon2_direct_exe);

    // Add debug_poseidon2_comprehensive binary
    const debug_poseidon2_comprehensive_exe = b.addExecutable(.{
        .name = "debug_poseidon2_comprehensive",
        .root_source_file = b.path("src/debug_poseidon2_comprehensive.zig"),
        .target = target,
        .optimize = optimize,
    });
    debug_poseidon2_comprehensive_exe.root_module.addImport("hash-zig", hash_zig_module);
    b.installArtifact(debug_poseidon2_comprehensive_exe);

    // Add debug_poseidon2_components_detailed binary
    const debug_poseidon2_components_detailed_exe = b.addExecutable(.{
        .name = "debug_poseidon2_components_detailed",
        .root_source_file = b.path("src/debug_poseidon2_components_detailed.zig"),
        .target = target,
        .optimize = optimize,
    });
    debug_poseidon2_components_detailed_exe.root_module.addImport("hash-zig", hash_zig_module);
    b.installArtifact(debug_poseidon2_components_detailed_exe);

    // Add debug_poseidon2_direct_permutation binary
    const debug_poseidon2_direct_permutation_exe = b.addExecutable(.{
        .name = "debug_poseidon2_direct_permutation",
        .root_source_file = b.path("src/debug_poseidon2_direct_permutation.zig"),
        .target = target,
        .optimize = optimize,
    });
    debug_poseidon2_direct_permutation_exe.root_module.addImport("hash-zig", hash_zig_module);
    b.installArtifact(debug_poseidon2_direct_permutation_exe);

    // Add debug_poseidon2_algorithm_components binary
    const debug_poseidon2_algorithm_components_exe = b.addExecutable(.{
        .name = "debug_poseidon2_algorithm_components",
        .root_source_file = b.path("src/debug_poseidon2_algorithm_components.zig"),
        .target = target,
        .optimize = optimize,
    });
    debug_poseidon2_algorithm_components_exe.root_module.addImport("hash-zig", hash_zig_module);
    b.installArtifact(debug_poseidon2_algorithm_components_exe);

    // Add debug_poseidon2_step_by_step_permutation binary
    const debug_poseidon2_step_permutation_exe = b.addExecutable(.{
        .name = "debug_poseidon2_step_by_step_permutation",
        .root_source_file = b.path("src/debug_poseidon2_step_by_step_permutation.zig"),
        .target = target,
        .optimize = optimize,
    });
    debug_poseidon2_step_permutation_exe.root_module.addImport("hash-zig", hash_zig_module);
    b.installArtifact(debug_poseidon2_step_permutation_exe);

    // Add debug_poseidon2_final_investigation binary
    const debug_poseidon2_final_investigation_exe = b.addExecutable(.{
        .name = "debug_poseidon2_final_investigation",
        .root_source_file = b.path("src/debug_poseidon2_final_investigation.zig"),
        .target = target,
        .optimize = optimize,
    });
    debug_poseidon2_final_investigation_exe.root_module.addImport("hash-zig", hash_zig_module);
    b.installArtifact(debug_poseidon2_final_investigation_exe);

    // Add debug_poseidon2_component_analysis binary
    const debug_poseidon2_component_analysis_exe = b.addExecutable(.{
        .name = "debug_poseidon2_component_analysis",
        .root_source_file = b.path("src/debug_poseidon2_component_analysis.zig"),
        .target = target,
        .optimize = optimize,
    });
    debug_poseidon2_component_analysis_exe.root_module.addImport("hash-zig", hash_zig_module);
    b.installArtifact(debug_poseidon2_component_analysis_exe);

    // Add debug_poseidon2_direct_permutation_test binary
    const debug_poseidon2_direct_permutation_test_exe = b.addExecutable(.{
        .name = "debug_poseidon2_direct_permutation_test",
        .root_source_file = b.path("src/debug_poseidon2_direct_permutation_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    debug_poseidon2_direct_permutation_test_exe.root_module.addImport("hash-zig", hash_zig_module);
    b.installArtifact(debug_poseidon2_direct_permutation_test_exe);

    // Add debug_poseidon2_16_direct binary
    const debug_poseidon2_16_direct_exe = b.addExecutable(.{
        .name = "debug_poseidon2_16_direct",
        .root_source_file = b.path("src/debug_poseidon2_16_direct.zig"),
        .target = target,
        .optimize = optimize,
    });
    debug_poseidon2_16_direct_exe.root_module.addImport("hash-zig", hash_zig_module);
    b.installArtifact(debug_poseidon2_16_direct_exe);

    // Add debug_poseidon2_verification binary
    const debug_poseidon2_verification_exe = b.addExecutable(.{
        .name = "debug_poseidon2_verification",
        .root_source_file = b.path("src/debug_poseidon2_verification.zig"),
        .target = target,
        .optimize = optimize,
    });
    debug_poseidon2_verification_exe.root_module.addImport("hash-zig", hash_zig_module);
    b.installArtifact(debug_poseidon2_verification_exe);

    // Add debug_leaf_domain_fixed binary
    const debug_leaf_domain_fixed_exe = b.addExecutable(.{
        .name = "debug_leaf_domain_fixed",
        .root_source_file = b.path("src/debug_leaf_domain_fixed.zig"),
        .target = target,
        .optimize = optimize,
    });
    debug_leaf_domain_fixed_exe.root_module.addImport("hash-zig", hash_zig_module);
    b.installArtifact(debug_leaf_domain_fixed_exe);
}
