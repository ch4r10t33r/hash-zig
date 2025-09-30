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
}
