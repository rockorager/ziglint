const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "ziglint",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the application");
    run_step.dependOn(&run_cmd.step);

    const test_step = b.step("test", "Run unit tests");
    const exe_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    test_step.dependOn(&b.addRunArtifact(exe_tests).step);

    const fmt_check = b.addFmt(.{ .paths = &.{ "src", "build.zig", "build.zig.zon" } });
    test_step.dependOn(&fmt_check.step);

    const lint_step = addLint(b, exe, &.{ "src", "build.zig" });
    test_step.dependOn(lint_step);
}

/// Add a ziglint step to your build. Use as a dependency to run linting.
/// Example usage in a downstream project:
/// ```zig
/// const ziglint_dep = b.dependency("ziglint", .{});
/// const lint_step = ziglint.addLint(b, ziglint_dep, &.{ "src", "build.zig" });
/// b.step("lint", "Run ziglint").dependOn(lint_step);
/// ```
pub fn addLint(
    b: *std.Build,
    ziglint_dep: anytype,
    paths: []const []const u8,
) *std.Build.Step {
    const exe = switch (@TypeOf(ziglint_dep)) {
        *std.Build.Step.Compile => ziglint_dep,
        *std.Build.Dependency => ziglint_dep.artifact("ziglint"),
        else => @compileError("expected *Compile or *Dependency"),
    };

    const run = b.addRunArtifact(exe);
    run.addArgs(paths);
    run.expectExitCode(0);
    return &run.step;
}
