//! `--explain` and `--list-rules` output.
//!
//! The body comes from the same markdown the doc tests run, so the explanation
//! a user reads is the one CI validated. The header adds what a doc file cannot
//! know: the rule's state and configuration for the project being linted.

const std = @import("std");
const rules = @import("rules.zig");
const FileConfig = @import("Config.zig");
const rule_docs = @import("rule_docs.zig");

const yellow = "\x1b[33m";
const dim = "\x1b[2m";
const reset = "\x1b[0m";

/// One line per rule: code, title, and whether the default disables it.
pub fn printIndex(writer: *std.Io.Writer, use_color: bool) !void {
    const y = if (use_color) yellow else "";
    const d = if (use_color) dim else "";
    const r = if (use_color) reset else "";

    inline for (std.meta.fields(rules.Rule)) |field| {
        const rule: rules.Rule = @enumFromInt(field.value);
        const meta = rule_docs.parseFrontmatter(rule_docs.get(field.name));
        try writer.print("{s}{s}{s}  {s}", .{ y, field.name, r, meta.title });
        if (!rule.defaultEnabled()) {
            try writer.print("{s} (disabled by default){s}", .{ d, r });
        }
        try writer.writeByte('\n');
    }
}

/// Full documentation for one rule, with the effective configuration first.
pub fn printRule(writer: *std.Io.Writer, rule: rules.Rule, config: *const FileConfig, use_color: bool) !void {
    const y = if (use_color) yellow else "";
    const d = if (use_color) dim else "";
    const r = if (use_color) reset else "";

    const raw = rule.documentation();
    const meta = rule_docs.parseFrontmatter(raw);

    try writer.print("{s}{s}{s}: {s}\n", .{ y, rule.code(), r, meta.title });
    try writeStatus(writer, rule, config, d, r);
    try writeConfigOverrides(writer, rule, config, d, r);
    try writer.writeByte('\n');
    try rule_docs.writeBody(writer, raw);
}

fn writeStatus(writer: *std.Io.Writer, rule: rules.Rule, config: *const FileConfig, d: []const u8, r: []const u8) !void {
    const enabled = config.isRuleEnabled(rule);
    const default_enabled = rule.defaultEnabled();

    if (enabled != default_enabled) {
        try writer.print("{s}enabled: {} (default: {}){s}\n", .{ d, enabled, default_enabled, r });
    } else if (!default_enabled) {
        try writer.print("{s}disabled by default{s}\n", .{ d, r });
    }
}

/// Prints settings the project changed from the defaults. A rule with no
/// overrides prints nothing, so the header stays out of the way.
fn writeConfigOverrides(writer: *std.Io.Writer, rule: rules.Rule, config: *const FileConfig, d: []const u8, r: []const u8) !void {
    inline for (@typeInfo(rules.Rule).@"enum".fields) |field| {
        if (field.value == @intFromEnum(rule)) {
            const rule_config = @field(config.rules, field.name);
            const Defaults = @TypeOf(rule_config);
            inline for (std.meta.fields(Defaults)) |cfg_field| {
                if (cfg_field.type == bool) continue; // handled by writeStatus
                const effective = @field(rule_config, cfg_field.name);
                const default = @field(Defaults{}, cfg_field.name);
                if (effective != default) {
                    try writer.print("{s}{s}: {} (default: {}){s}\n", .{ d, cfg_field.name, effective, default, r });
                }
            }
        }
    }
}

test "printRule shows the title and the project override" {
    var config: FileConfig = .{};
    config.rules.Z024.max_length = 255;

    var buf: [4096]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buf);
    try printRule(&writer, .Z024, &config, false);

    const output = writer.buffered();
    try std.testing.expect(std.mem.startsWith(u8, output, "Z024: Line exceeds maximum length\n"));
    try std.testing.expect(std.mem.find(u8, output, "max_length: 255 (default: 120)") != null);
    try std.testing.expect(std.mem.find(u8, output, "## Examples") != null);
}

test "printRule omits overrides at their default" {
    const config: FileConfig = .{};

    var buf: [4096]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buf);
    try printRule(&writer, .Z024, &config, false);

    try std.testing.expect(std.mem.find(u8, writer.buffered(), "max_length: ") == null);
}

test "printRule reports a disabled-by-default rule" {
    const config: FileConfig = .{};

    var buf: [4096]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buf);
    try printRule(&writer, .Z033, &config, false);

    try std.testing.expect(std.mem.find(u8, writer.buffered(), "disabled by default") != null);
}

test "printIndex lists every rule" {
    var buf: [8192]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buf);
    try printIndex(&writer, false);

    const output = writer.buffered();
    try std.testing.expect(std.mem.find(u8, output, "Z001  Function names should be camelCase") != null);
    try std.testing.expect(std.mem.find(u8, output, "Z033") != null);
    try std.testing.expect(std.mem.find(u8, output, "(disabled by default)") != null);
}
