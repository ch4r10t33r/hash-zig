const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const enable_docs = b.option(bool, "docs", "Enable docs generation") orelse false;

    // Create the module
    const hash_zig_module = b.addModule("hash-zig", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

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
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_unit_tests.step);

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

    // Add SIMD modules
    const simd_winternitz_module = b.addModule("simd_winternitz", .{
        .root_source_file = b.path("src/simd_winternitz.zig"),
        .target = target,
        .optimize = optimize,
    });

    const simd_poseidon2_module = b.addModule("simd_poseidon2", .{
        .root_source_file = b.path("src/poseidon2/simd_poseidon2.zig"),
        .target = target,
        .optimize = optimize,
    });

    const simd_montgomery_module = b.addModule("simd_montgomery", .{
        .root_source_file = b.path("src/poseidon2/fields/koalabear/simd_montgomery.zig"),
        .target = target,
        .optimize = optimize,
    });

    const simd_signature_module = b.addModule("simd_signature", .{
        .root_source_file = b.path("src/simd_signature.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Set up module dependencies
    simd_signature_module.addImport("simd_winternitz", simd_winternitz_module);
    simd_signature_module.addImport("simd_poseidon2", simd_poseidon2_module);
    simd_signature_module.addImport("hash-zig", hash_zig_module);
    // Do not add a separate params module; code should use @import("hash-zig").params

    simd_winternitz_module.addImport("simd_montgomery", simd_montgomery_module);
    simd_winternitz_module.addImport("simd_poseidon2", simd_poseidon2_module);

    simd_poseidon2_module.addImport("simd_montgomery", simd_montgomery_module);

    // SIMD benchmark executable
    const simd_benchmark = b.addExecutable(.{
        .name = "hash-zig-simd-benchmark",
        .root_source_file = b.path("examples/simd_benchmark.zig"),
        .target = target,
        .optimize = optimize,
    });
    // Only attach 'hash-zig' as the root module once to avoid duplicate module roots
    simd_benchmark.root_module.addImport("hash-zig", hash_zig_module);
    simd_benchmark.root_module.addImport("simd_signature", simd_signature_module);
    simd_benchmark.root_module.addImport("simd_winternitz", simd_winternitz_module);
    simd_benchmark.root_module.addImport("simd_poseidon2", simd_poseidon2_module);
    simd_benchmark.root_module.addImport("simd_montgomery", simd_montgomery_module);
    b.installArtifact(simd_benchmark);

    const run_simd_benchmark = b.addRunArtifact(simd_benchmark);
    const simd_benchmark_step = b.step("simd-benchmark", "Run SIMD performance benchmark");
    simd_benchmark_step.dependOn(&run_simd_benchmark.step);

    // (Optimized benchmark and comparison disabled - implementations now match Rust)

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
