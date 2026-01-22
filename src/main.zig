//! ziglint - A linter for Zig source code

const std = @import("std");
const Linter = @import("Linter.zig");

pub fn main() !u8 {
    var arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var stdout_buf: [4096]u8 = undefined;
    var stdout = std.fs.File.stdout().writer(&stdout_buf);
    defer stdout.end() catch {};

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        try printUsage(&stdout.interface);
        return 1;
    }

    var total_issues: usize = 0;
    for (args[1..]) |path| {
        total_issues += try lintPath(allocator, path, &stdout.interface);
    }

    return if (total_issues > 0) 1 else 0;
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
        \\Usage: ziglint <paths...>
        \\
        \\Lint Zig source files for style and correctness issues.
        \\Directories are scanned recursively for .zig files.
        \\
    );
}

test {
    _ = Linter;
    _ = @import("rules.zig");
}
