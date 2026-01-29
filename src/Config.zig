//! Configuration file loading and parsing for ziglint.
//! Supports .ziglint.zon config files with rule-specific settings.

const std = @import("std");

const Rule = @import("rules.zig").Rule;

const Config = @This();

/// Global settings
paths: []const []const u8 = &.{},

/// Per-rule configuration
rules: Rule.Config = .{},

/// Returns the effective line length limit for Z024.
pub fn getLineLength(self: *const Config) u32 {
    return self.rules.Z024.max_length;
}

/// Check if a rule is enabled (considering config).
pub fn isRuleEnabled(self: *const Config, rule: Rule) bool {
    inline for (@typeInfo(Rule).@"enum".fields) |field| {
        if (field.value == @intFromEnum(rule)) {
            return @field(self.rules, field.name).enabled;
        }
    }
    return true;
}

/// Load config from .ziglint.zon file, searching from start_path up to root.
pub fn load(allocator: std.mem.Allocator, start_path: ?[]const u8) !Config {
    const config_path = try findConfigFile(allocator, start_path) orelse return .{};
    defer allocator.free(config_path);

    return parseConfigFile(allocator, config_path) catch |err| {
        std.debug.print("warning: failed to parse {s}: {}\n", .{ config_path, err });
        return .{};
    };
}

/// Find .ziglint.zon by walking up from start_path.
fn findConfigFile(allocator: std.mem.Allocator, start_path: ?[]const u8) !?[]const u8 {
    const path = start_path orelse {
        return findConfigInDir(allocator, ".");
    };

    const abs_path = std.fs.cwd().realpathAlloc(allocator, path) catch path;
    defer if (abs_path.ptr != path.ptr) allocator.free(abs_path);

    var current = abs_path;
    while (true) {
        if (try findConfigInDir(allocator, current)) |config_path| {
            return config_path;
        }

        const parent = std.fs.path.dirname(current) orelse break;
        if (std.mem.eql(u8, parent, current)) break;
        current = parent;
    }

    return null;
}

fn findConfigInDir(allocator: std.mem.Allocator, dir_path: []const u8) !?[]const u8 {
    const config_path = try std.fs.path.join(allocator, &.{ dir_path, ".ziglint.zon" });
    errdefer allocator.free(config_path);

    std.fs.cwd().access(config_path, .{}) catch {
        allocator.free(config_path);
        return null;
    };

    return config_path;
}

/// ZON schema for the config file
const ZonConfig = struct {
    paths: ?[]const []const u8 = null,
    rules: ?Rule.Config = null,
};

fn parseConfigFile(allocator: std.mem.Allocator, path: []const u8) !Config {
    const source = try std.fs.cwd().readFileAllocOptions(
        allocator,
        path,
        1024 * 1024,
        null,
        .@"1",
        0,
    );
    defer allocator.free(source);

    return parseConfigSource(allocator, source);
}

fn parseConfigSource(allocator: std.mem.Allocator, source: [:0]const u8) !Config {
    const zon_config = std.zon.parse.fromSlice(ZonConfig, allocator, source, null, .{}) catch {
        return error.ParseError;
    };
    defer std.zon.parse.free(allocator, zon_config);

    var config: Config = .{};

    if (zon_config.paths) |zon_paths| {
        var paths_list: std.ArrayList([]const u8) = .empty;
        errdefer {
            for (paths_list.items) |item| allocator.free(item);
            paths_list.deinit(allocator);
        }
        for (zon_paths) |p| {
            try paths_list.append(allocator, try allocator.dupe(u8, p));
        }
        config.paths = try paths_list.toOwnedSlice(allocator);
    }

    if (zon_config.rules) |zon_rules| {
        config.rules = zon_rules;
    }

    return config;
}

// Tests
test "default config" {
    const config: Config = .{};
    try std.testing.expectEqual(120, config.getLineLength());
    try std.testing.expect(config.isRuleEnabled(.Z001));
    try std.testing.expect(config.isRuleEnabled(.Z024));
}

test "parse simple config" {
    const source =
        \\.{
        \\    .rules = .{
        \\        .Z024 = .{ .max_length = 100 },
        \\    },
        \\}
    ;
    const config = try parseConfigSource(std.testing.allocator, source);
    try std.testing.expectEqual(100, config.getLineLength());
}

test "parse rules config" {
    const source =
        \\.{
        \\    .rules = .{
        \\        .Z001 = .{ .enabled = false },
        \\        .Z024 = .{ .max_length = 80 },
        \\    },
        \\}
    ;
    const config = try parseConfigSource(std.testing.allocator, source);
    try std.testing.expect(!config.isRuleEnabled(.Z001));
    try std.testing.expect(config.isRuleEnabled(.Z024));
    try std.testing.expectEqual(80, config.getLineLength());
}

test "runtime rule check" {
    const config: Config = .{};
    const rule: Rule = .Z001;
    try std.testing.expect(config.isRuleEnabled(rule));
}

test "parse paths config" {
    const source =
        \\.{
        \\    .paths = .{
        \\        "src",
        \\        "lib",
        \\    },
        \\}
    ;
    const config = try parseConfigSource(std.testing.allocator, source);
    defer {
        for (config.paths) |item| std.testing.allocator.free(item);
        std.testing.allocator.free(config.paths);
    }
    try std.testing.expectEqual(2, config.paths.len);
    try std.testing.expectEqualStrings("src", config.paths[0]);
    try std.testing.expectEqualStrings("lib", config.paths[1]);
}
