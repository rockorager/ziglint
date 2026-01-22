//! ziglint - A linter for Zig source code

const std = @import("std");
const Linter = @import("Linter.zig");
const ModuleGraph = @import("ModuleGraph.zig");

pub const Config = struct {
    root_source: ?[]const u8 = null,
    zig_lib_path: ?[]const u8 = null,
    paths: []const []const u8 = &.{},
};

pub fn main() !u8 {
    var arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var stdout_buf: [4096]u8 = undefined;
    var stdout = std.fs.File.stdout().writer(&stdout_buf);
    defer stdout.end() catch {};

    const config = parseArgs(allocator, &stdout.interface) catch |err| switch (err) {
        error.InvalidArgs => return 1,
        else => return err,
    };

    if (config.root_source) |root| {
        return runSemanticMode(allocator, root, config.zig_lib_path, &stdout.interface);
    }

    if (config.paths.len == 0) {
        try printUsage(&stdout.interface);
        return 1;
    }

    var total_issues: usize = 0;
    for (config.paths) |path| {
        total_issues += try lintPath(allocator, path, &stdout.interface);
    }

    return if (total_issues > 0) 1 else 0;
}

fn parseArgs(allocator: std.mem.Allocator, writer: *std.Io.Writer) !Config {
    const args = try std.process.argsAlloc(allocator);

    var config: Config = .{};
    var paths: std.ArrayListUnmanaged([]const u8) = .empty;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--root")) {
            i += 1;
            if (i >= args.len) {
                try writer.writeAll("error: --root requires a file path argument\n");
                return error.InvalidArgs;
            }
            config.root_source = args[i];
        } else if (std.mem.eql(u8, arg, "--zig-lib-path")) {
            i += 1;
            if (i >= args.len) {
                try writer.writeAll("error: --zig-lib-path requires a path argument\n");
                return error.InvalidArgs;
            }
            config.zig_lib_path = args[i];
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            try printUsage(writer);
            return error.InvalidArgs;
        } else if (std.mem.startsWith(u8, arg, "-")) {
            try writer.print("error: unknown option '{s}'\n", .{arg});
            return error.InvalidArgs;
        } else {
            try paths.append(allocator, arg);
        }
    }

    config.paths = paths.items;
    return config;
}

fn runSemanticMode(
    allocator: std.mem.Allocator,
    root_source: []const u8,
    explicit_lib_path: ?[]const u8,
    writer: *std.Io.Writer,
) !u8 {
    const zig_lib_path = explicit_lib_path orelse try detectZigLibPath(allocator, writer);

    var graph = ModuleGraph.init(allocator, root_source, zig_lib_path) catch |err| {
        try writer.print("error: could not build module graph: {}\n", .{err});
        return 1;
    };
    defer graph.deinit();

    try writer.print("semantic mode: parsed {} modules from root={s}\n", .{ graph.moduleCount(), root_source });
    return 0;
}

fn detectZigLibPath(allocator: std.mem.Allocator, writer: *std.Io.Writer) !?[]const u8 {
    var child: std.process.Child = .init(&.{ "zig", "env" }, allocator);
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Ignore;

    child.spawn() catch |err| {
        try writer.print("warning: could not run 'zig env': {}\n", .{err});
        return null;
    };

    var buf: [64 * 1024]u8 = undefined;
    const stdout = child.stdout orelse return null;
    const len = stdout.readAll(&buf) catch return null;
    const output = buf[0..len];

    const term = child.wait() catch return null;
    switch (term) {
        .Exited => |code| if (code != 0) return null,
        else => return null,
    }

    return parseLibDirFromZigEnv(allocator, output);
}

fn parseLibDirFromZigEnv(allocator: std.mem.Allocator, output: []const u8) ?[]const u8 {
    const needle = ".lib_dir = \"";
    const start_idx = std.mem.indexOf(u8, output, needle) orelse return null;
    const value_start = start_idx + needle.len;
    const end_idx = std.mem.indexOfPos(u8, output, value_start, "\"") orelse return null;
    return allocator.dupe(u8, output[value_start..end_idx]) catch null;
}

fn lintPath(allocator: std.mem.Allocator, path: []const u8, writer: *std.Io.Writer) !usize {
    const stat = std.fs.cwd().statFile(path) catch |err| {
        try writer.print("error: cannot access '{s}': {}\n", .{ path, err });
        return 0;
    };

    if (stat.kind == .directory) {
        return lintDirectory(allocator, path, writer);
    }

    return lintFile(allocator, path, writer);
}

fn lintDirectory(allocator: std.mem.Allocator, path: []const u8, writer: *std.Io.Writer) !usize {
    var dir = std.fs.cwd().openDir(path, .{ .iterate = true }) catch |err| {
        try writer.print("error: cannot open directory '{s}': {}\n", .{ path, err });
        return 0;
    };
    defer dir.close();

    const gitignore = loadGitignore(allocator, dir);
    defer if (gitignore) |g| allocator.free(g);

    var total: usize = 0;
    var walker = dir.walk(allocator) catch |err| {
        try writer.print("error: cannot walk directory '{s}': {}\n", .{ path, err });
        return 0;
    };
    defer walker.deinit();

    while (walker.next() catch null) |entry| {
        if (shouldSkip(entry.path, gitignore)) continue;
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.basename, ".zig")) continue;

        const full_path = std.fs.path.join(allocator, &.{ path, entry.path }) catch continue;
        defer allocator.free(full_path);

        total += try lintFile(allocator, full_path, writer);
    }

    return total;
}

fn shouldSkip(path: []const u8, gitignore: ?[]const u8) bool {
    var iter = std.mem.splitScalar(u8, path, std.fs.path.sep);
    while (iter.next()) |component| {
        if (std.mem.startsWith(u8, component, ".")) return true;
        if (std.mem.eql(u8, component, "zig-cache")) return true;
        if (std.mem.eql(u8, component, "zig-out")) return true;
    }

    if (gitignore) |patterns| {
        var lines = std.mem.splitScalar(u8, patterns, '\n');
        while (lines.next()) |line| {
            const pattern = std.mem.trim(u8, line, &std.ascii.whitespace);
            if (pattern.len == 0 or pattern[0] == '#') continue;
            if (matchesGitignore(path, pattern)) return true;
        }
    }

    return false;
}

fn matchesGitignore(path: []const u8, pattern: []const u8) bool {
    const clean_pattern = if (std.mem.endsWith(u8, pattern, "/"))
        pattern[0 .. pattern.len - 1]
    else
        pattern;

    if (std.mem.startsWith(u8, clean_pattern, "/")) {
        return std.mem.startsWith(u8, path, clean_pattern[1..]);
    }

    var iter = std.mem.splitScalar(u8, path, std.fs.path.sep);
    while (iter.next()) |component| {
        if (std.mem.eql(u8, component, clean_pattern)) return true;
    }

    return std.mem.indexOf(u8, path, clean_pattern) != null;
}

fn loadGitignore(allocator: std.mem.Allocator, dir: std.fs.Dir) ?[]const u8 {
    return dir.readFileAlloc(allocator, ".gitignore", 1024 * 64) catch null;
}

fn lintFile(allocator: std.mem.Allocator, path: []const u8, writer: *std.Io.Writer) !usize {
    const source = std.fs.cwd().readFileAllocOptions(
        allocator,
        path,
        1024 * 1024 * 16,
        null,
        .@"1",
        0,
    ) catch |err| {
        try writer.print("error: cannot read '{s}': {}\n", .{ path, err });
        return 0;
    };
    defer allocator.free(source);

    var linter: Linter = .init(allocator, source, path);
    defer linter.deinit();

    linter.lint();

    for (linter.diagnostics.items) |diag| {
        try diag.write(writer);
    }

    return linter.diagnostics.items.len;
}

fn printUsage(writer: *std.Io.Writer) !void {
    try writer.writeAll(
        \\Usage: ziglint [options] <paths...>
        \\       ziglint --root <file> [options]
        \\
        \\Lint Zig source files for style and correctness issues.
        \\
        \\Options:
        \\  --root <file>         Enable semantic analysis mode with the given root source file.
        \\                        This enables cross-file type resolution and additional checks.
        \\  --zig-lib-path <path> Override the path to the Zig standard library.
        \\                        Auto-detected from 'zig env' if not specified.
        \\  -h, --help            Show this help message.
        \\
        \\When run without --root, directories are scanned recursively for .zig files.
        \\
    );
}

test {
    _ = Linter;
    _ = ModuleGraph;
    _ = @import("rules.zig");
    _ = @import("doc_comments.zig");
    _ = @import("TypeResolver.zig");
}

test "parseLibDirFromZigEnv" {
    const output =
        \\.{
        \\    .zig_exe = "/usr/bin/zig",
        \\    .lib_dir = "/usr/lib/zig",
        \\    .std_dir = "/usr/lib/zig/std",
        \\}
    ;
    const result = parseLibDirFromZigEnv(std.testing.allocator, output);
    defer if (result) |r| std.testing.allocator.free(r);
    try std.testing.expectEqualStrings("/usr/lib/zig", result.?);
}

test "parseLibDirFromZigEnv: missing field" {
    const output = ".{ .zig_exe = \"/usr/bin/zig\" }";
    try std.testing.expectEqual(null, parseLibDirFromZigEnv(std.testing.allocator, output));
}
