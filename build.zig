const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const version = getVersion(b);

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    const options = b.addOptions();
    options.addOption([]const u8, "version", version);
    exe_mod.addOptions("build_options", options);

    const exe = b.addExecutable(.{
        .name = "ziglint",
        .root_module = exe_mod,
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
    const test_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    test_mod.addOptions("build_options", options);
    const exe_tests = b.addTest(.{
        .root_module = test_mod,
    });
    test_step.dependOn(&b.addRunArtifact(exe_tests).step);

    const fmt_check = b.addFmt(.{ .paths = &.{ "src", "build.zig", "build.zig.zon" } });
    test_step.dependOn(&fmt_check.step);

    const lint_step = addLint(b, exe, &.{ "src", "build.zig" });
    test_step.dependOn(lint_step);
}

/// Add a ziglint step to your build. Use as a dependency to run linting.
/// The ziglint executable is always built with ReleaseFast for speed.
/// Example usage in a downstream project:
/// ```zig
/// const ziglint_dep = b.dependency("ziglint", .{ .optimize = .ReleaseFast });
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
        *const std.Build.Dependency => ziglint_dep.artifact("ziglint"),
        else => @compileError("expected *Compile or *Dependency"),
    };

    const run = b.addRunArtifact(exe);
    run.addArgs(paths);
    run.expectExitCode(0);
    return &run.step;
}

fn getVersion(b: *std.Build) []const u8 {
    var code: u8 = undefined;
    const git_describe = b.runAllowFail(&.{ "git", "describe", "--match", "v*.*.*", "--tags" }, &code, .Ignore) catch {
        return "unknown";
    };
    const trimmed = std.mem.trim(u8, git_describe, " \n\r");
    const without_v = if (trimmed.len > 0 and trimmed[0] == 'v') trimmed[1..] else trimmed;

    if (std.mem.indexOfScalar(u8, without_v, '-')) |dash_idx| {
        const tag_part = without_v[0..dash_idx];
        const rest = without_v[dash_idx + 1 ..];
        if (std.mem.indexOfScalar(u8, rest, '-')) |second_dash| {
            const count = rest[0..second_dash];
            const hash = rest[second_dash + 1 ..];
            const hash_without_g = if (hash.len > 0 and hash[0] == 'g') hash[1..] else hash;
            return b.fmt("{s}-{s}+{s}", .{ tag_part, count, hash_without_g });
        }
    }
    return without_v;
}
