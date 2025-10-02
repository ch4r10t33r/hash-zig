const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

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

    // Lint (using zlinter)
    const zlinter = @import("zlinter");
    const lint_step = b.step("lint", "Run zlinter");
    lint_step.dependOn(step: {
        var builder = zlinter.builder(b, .{});
        builder.addPaths(.{
            .include = &.{ b.path("src/"), b.path("examples/"), b.path("test/") },
        });
        builder.addRule(.{ .builtin = .field_naming }, .{});
        builder.addRule(.{ .builtin = .declaration_naming }, .{});
        builder.addRule(.{ .builtin = .function_naming }, .{});
        builder.addRule(.{ .builtin = .no_unused }, .{});
        builder.addRule(.{ .builtin = .no_deprecated }, .{});
        break :step builder.build();
    });

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

    // Profiling executable
    const profiling_module = b.createModule(.{
        .root_source_file = b.path("examples/profiling.zig"),
        .target = target,
        .optimize = optimize,
    });
    profiling_module.addImport("hash-zig", hash_zig_module);

    const profiling = b.addExecutable(.{
        .name = "hash-zig-profile",
        .root_module = profiling_module,
    });
    b.installArtifact(profiling);

    const run_profiling = b.addRunArtifact(profiling);
    const profile_step = b.step("profile", "Run profiling analysis");
    profile_step.dependOn(&run_profiling.step);

    // Optimized benchmark executable (commented out for now)
    // const optimized_benchmark_module = b.createModule(.{
    //     .root_source_file = b.path("examples/optimized_benchmark.zig"),
    //     .target = target,
    //     .optimize = optimize,
    // });
    // optimized_benchmark_module.addImport("hash-zig", hash_zig_module);
    // optimized_benchmark_module.addImport("optimized_signature", b.addModule("optimized_signature", .{
    //     .root_source_file = b.path("src/optimized_signature.zig"),
    //     .target = target,
    //     .optimize = optimize,
    // }));

    // const optimized_benchmark = b.addExecutable(.{
    //     .name = "hash-zig-optimized-benchmark",
    //     .root_module = optimized_benchmark_module,
    // });
    // b.installArtifact(optimized_benchmark);

    // const run_optimized_benchmark = b.addRunArtifact(optimized_benchmark);
    // const optimized_benchmark_step = b.step("optimized-benchmark", "Run optimized performance benchmark");
    // optimized_benchmark_step.dependOn(&run_optimized_benchmark.step);

    // Documentation (separate from main library build)
    const docs_obj = b.addObject(.{
        .name = "hash-zig-docs",
        .root_module = hash_zig_module,
    });
    const install_docs = b.addInstallDirectory(.{
        .source_dir = docs_obj.getEmittedDocs(),
        .install_dir = .prefix,
        .install_subdir = "docs",
    });
    const docs_step = b.step("docs", "Generate documentation");
    docs_step.dependOn(&install_docs.step);
}
