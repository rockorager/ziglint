//! ziglint - A linter for Zig source code

const std = @import("std");
const build_options = @import("build_options");
pub const version = build_options.version;

const FileConfig = @import("Config.zig");
const Linter = @import("Linter.zig");
const ModuleGraph = @import("ModuleGraph.zig");
const rules = @import("rules.zig");
const TypeResolver = @import("TypeResolver.zig");

pub const Config = struct {
    zig_lib_path: ?[]const u8 = null,
    paths: []const []const u8 = &.{},
    ignored_rules: []const rules.Rule = &.{},
    file_config: FileConfig = .{},
};

pub fn main() !u8 {
    var arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const stderr_file = std.fs.File.stderr();
    const use_color = detectColorSupport(stderr_file);

    var stdout_buf: [4096]u8 = undefined;
    var stdout = std.fs.File.stdout().writer(&stdout_buf);
    defer stdout.end() catch {};

    var stderr_buf: [4096]u8 = undefined;
    var stderr = stderr_file.writer(&stderr_buf);
    defer stderr.end() catch {};

    var config = parseArgs(allocator, &stderr.interface) catch |err| switch (err) {
        error.InvalidArgs => return 1,
        else => return err,
    };

    // Load config file from first CLI path (or current directory)
    const start_path = if (config.paths.len > 0) config.paths[0] else null;
    config.file_config = FileConfig.load(allocator, start_path) catch .{};

    // Use CLI paths, then config file paths, then default to "."
    if (config.paths.len == 0) {
        if (config.file_config.paths.len > 0) {
            config.paths = config.file_config.paths;
        } else {
            config.paths = &.{"."};
        }
    }

    const zig_lib_path = config.zig_lib_path orelse detectZigLibPath(allocator, &stderr.interface) catch null;

    var total_issues: usize = 0;
    for (config.paths) |path| {
        const abs_path = std.fs.cwd().realpathAlloc(allocator, path) catch path;
        const project_root = findProjectRoot(abs_path);
        total_issues += try lintPath(allocator, path, zig_lib_path, &config, use_color, project_root, &stderr.interface);
    }

    return if (total_issues > 0) 1 else 0;
}

fn detectColorSupport(file: std.fs.File) bool {
    const native = @import("builtin").os.tag;
    // NO_COLOR takes precedence (https://no-color.org/)
    if (native == .windows) {
        if (std.process.getenvW(std.unicode.utf8ToUtf16LeStringLiteral("NO_COLOR"))) |_| return false;
        if (std.process.getenvW(std.unicode.utf8ToUtf16LeStringLiteral("FORCE_COLOR"))) |_| return true;
    } else {
        if (std.posix.getenv("NO_COLOR")) |_| return false;
        if (std.posix.getenv("FORCE_COLOR")) |_| return true;
    }
    // Otherwise, use color if stdout is a TTY
    return file.isTty();
}

fn findProjectRoot(start_path: []const u8) ?[]const u8 {
    var path = start_path;
    while (true) {
        // Check if build.zig exists in this directory
        const build_zig = std.fs.path.join(std.heap.page_allocator, &.{ path, "build.zig" }) catch return null;
        defer std.heap.page_allocator.free(build_zig);

        if (std.fs.cwd().access(build_zig, .{})) |_| {
            return std.heap.page_allocator.dupe(u8, path) catch null;
        } else |_| {}

        // Move up one directory
        const parent = std.fs.path.dirname(path) orelse return null;
        if (std.mem.eql(u8, parent, path)) return null; // at root
        path = parent;
    }
}

fn makeRelativePath(path: []const u8, project_root: ?[]const u8) []const u8 {
    const root = project_root orelse return path;
    if (std.mem.startsWith(u8, path, root)) {
        var rel = path[root.len..];
        // Skip leading path separator
        if (rel.len > 0 and rel[0] == std.fs.path.sep) {
            rel = rel[1..];
        }
        if (rel.len > 0) return rel;
    }
    return path;
}

fn parseArgs(allocator: std.mem.Allocator, writer: *std.Io.Writer) !Config {
    const args = try std.process.argsAlloc(allocator);

    var config: Config = .{};
    var paths: std.ArrayListUnmanaged([]const u8) = .empty;
    var ignored_rules: std.ArrayListUnmanaged(rules.Rule) = .empty;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--zig-lib-path")) {
            i += 1;
            if (i >= args.len) {
                try writer.writeAll("error: --zig-lib-path requires a path argument\n");
                return error.InvalidArgs;
            }
            config.zig_lib_path = args[i];
        } else if (std.mem.eql(u8, arg, "--ignore")) {
            i += 1;
            if (i >= args.len) {
                try writer.writeAll("error: --ignore requires a rule code (e.g., Z001)\n");
                return error.InvalidArgs;
            }
            if (parseRuleCode(args[i])) |rule| {
                try ignored_rules.append(allocator, rule);
            } else {
                try writer.print("error: unknown rule code '{s}'\n", .{args[i]});
                return error.InvalidArgs;
            }
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            try printUsage(writer);
            return error.InvalidArgs;
        } else if (std.mem.eql(u8, arg, "--version") or std.mem.eql(u8, arg, "-v")) {
            try printVersion(writer);
            return error.InvalidArgs;
        } else if (std.mem.startsWith(u8, arg, "-")) {
            try writer.print("error: unknown option '{s}'\n", .{arg});
            return error.InvalidArgs;
        } else {
            try paths.append(allocator, arg);
        }
    }

    config.paths = paths.items;
    config.ignored_rules = ignored_rules.items;
    return config;
}

fn parseRuleCode(code: []const u8) ?rules.Rule {
    inline for (std.meta.fields(rules.Rule)) |field| {
        if (std.mem.eql(u8, code, field.name)) {
            return @enumFromInt(field.value);
        }
    }
    return null;
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

fn lintPath(allocator: std.mem.Allocator, path: []const u8, zig_lib_path: ?[]const u8, config: *const Config, use_color: bool, project_root: ?[]const u8, writer: *std.Io.Writer) !usize {
    const stat = std.fs.cwd().statFile(path) catch |err| {
        try writer.print("error: cannot access '{s}': {}\n", .{ path, err });
        return 0;
    };

    if (stat.kind == .directory) {
        return lintDirectory(allocator, path, zig_lib_path, config, use_color, project_root, writer);
    }

    return lintFile(allocator, path, zig_lib_path, config, use_color, project_root, writer);
}

fn lintDirectory(allocator: std.mem.Allocator, path: []const u8, zig_lib_path: ?[]const u8, config: *const Config, use_color: bool, project_root: ?[]const u8, writer: *std.Io.Writer) !usize {
    var dir = std.fs.cwd().openDir(path, .{ .iterate = true }) catch |err| {
        try writer.print("error: cannot open directory '{s}': {}\n", .{ path, err });
        return 0;
    };
    defer dir.close();

    const gitignore = loadGitignore(allocator, dir);
    defer if (gitignore) |g| allocator.free(g);

    // Collect all .zig files first
    var files: std.ArrayListUnmanaged([]const u8) = .empty;
    defer {
        for (files.items) |f| allocator.free(f);
        files.deinit(allocator);
    }

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
        files.append(allocator, full_path) catch {
            allocator.free(full_path);
            continue;
        };
    }

    if (files.items.len == 0) return 0;

    // Build module graph once using first file as root, then add all others
    var graph = ModuleGraph.init(allocator, files.items[0], zig_lib_path) catch {
        // Fall back to per-file linting without semantics
        var total: usize = 0;
        for (files.items) |file_path| {
            total += try lintFileSimple(allocator, file_path, config, use_color, project_root, writer);
        }
        return total;
    };
    defer graph.deinit();

    // Add remaining files to the graph
    for (files.items[1..]) |file_path| {
        graph.addModulePublic(file_path);
    }

    var resolver: TypeResolver = .init(allocator, &graph);
    defer resolver.deinit();

    var total: usize = 0;
    for (files.items) |file_path| {
        total += try lintFileWithGraph(allocator, file_path, &graph, &resolver, config, use_color, project_root, writer);
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

fn lintFile(allocator: std.mem.Allocator, path: []const u8, zig_lib_path: ?[]const u8, config: *const Config, use_color: bool, project_root: ?[]const u8, writer: *std.Io.Writer) !usize {
    var graph = ModuleGraph.init(allocator, path, zig_lib_path) catch {
        return lintFileSimple(allocator, path, config, use_color, project_root, writer);
    };
    defer graph.deinit();

    var resolver: TypeResolver = .init(allocator, &graph);
    defer resolver.deinit();

    return lintFileWithGraph(allocator, path, &graph, &resolver, config, use_color, project_root, writer);
}

fn lintFileSimple(allocator: std.mem.Allocator, path: []const u8, config: *const Config, use_color: bool, project_root: ?[]const u8, writer: *std.Io.Writer) !usize {
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

    var linter: Linter = .init(allocator, source, path, &config.file_config);
    defer linter.deinit();
    linter.lint();
    return writeDiagnostics(linter.diagnostics.items, config, use_color, project_root, writer);
}

fn lintFileWithGraph(allocator: std.mem.Allocator, path: []const u8, graph: *ModuleGraph, resolver: *TypeResolver, config: *const Config, use_color: bool, project_root: ?[]const u8, writer: *std.Io.Writer) !usize {
    const mod = graph.getModule(path) orelse {
        return lintFileSimple(allocator, path, config, use_color, project_root, writer);
    };

    var linter: Linter = .initWithSemantics(allocator, mod.source, mod.path, resolver, mod.path, &config.file_config);
    defer linter.deinit();

    linter.lint();

    return writeDiagnostics(linter.diagnostics.items, config, use_color, project_root, writer);
}

fn writeDiagnostics(diagnostics: []const Linter.Diagnostic, config: *const Config, use_color: bool, project_root: ?[]const u8, writer: *std.Io.Writer) !usize {
    var count: usize = 0;
    for (diagnostics) |diag| {
        // Check CLI ignore list
        var ignored = false;
        for (config.ignored_rules) |ignored_rule| {
            if (diag.rule == ignored_rule) {
                ignored = true;
                break;
            }
        }
        // Check config file rule enabled state
        if (!ignored and !config.file_config.isRuleEnabled(diag.rule)) {
            ignored = true;
        }
        if (!ignored) {
            const display_path = makeRelativePath(diag.path, project_root);
            try diag.write(writer, use_color, display_path);
            count += 1;
        }
    }
    return count;
}

fn printUsage(writer: *std.Io.Writer) !void {
    try writer.writeAll(
        \\Usage: ziglint [options] <paths...>
        \\
        \\Lint Zig source files for style and correctness issues.
        \\
        \\Options:
        \\  --ignore <rule>       Ignore a rule (e.g., Z001). Can be repeated.
        \\  --zig-lib-path <path> Override the path to the Zig standard library.
        \\                        Auto-detected from 'zig env' if not specified.
        \\  -h, --help            Show this help message.
        \\  -v, --version         Show version.
        \\
        \\Directories are scanned recursively for .zig files.
        \\
    );
}

fn printVersion(writer: *std.Io.Writer) !void {
    try writer.writeAll("ziglint " ++ version ++ "\n");
}

test {
    _ = Linter;
    _ = ModuleGraph;
    _ = FileConfig;
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
