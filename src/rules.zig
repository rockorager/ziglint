//! Lint rule definitions with unique identifiers.

pub const Rule = enum(u16) {
    Z001 = 1,
    Z002 = 2,
    Z003 = 3,
    Z004 = 4,
    Z005 = 5,
    Z006 = 6,
    Z007 = 7,
    Z008 = 8,
    Z009 = 9,
    Z010 = 10,
    Z011 = 11,
    Z012 = 12,
    Z013 = 13,
    Z014 = 14,
    Z015 = 15,

    pub fn code(self: Rule) []const u8 {
        return @tagName(self);
    }

    // ANSI escape codes
    const yellow = "\x1b[33m";
    const magenta = "\x1b[35m";
    const cyan = "\x1b[36m";
    const dim = "\x1b[2m";
    const reset = "\x1b[0m";

    pub fn writeMessage(self: Rule, writer: *std.Io.Writer, context: []const u8, use_color: bool) !void {
        const y = if (use_color) yellow else "";
        const m = if (use_color) magenta else "";
        const c = if (use_color) cyan else "";
        const d = if (use_color) dim else "";
        const r = if (use_color) reset else "";

        switch (self) {
            .Z001 => try writer.print("function {s}'{s}'{s} should be camelCase", .{ y, context, r }),
            .Z002 => try writer.print("variable {s}'{s}'{s} is unused but has a value", .{ y, context, r }),
            .Z003 => try writer.writeAll("parse error"),
            // syntax highlight: `const name: T = .{};` vs `const name = T{};`
            .Z004 => try writer.print("prefer {s}`{s}{s}const{s} {s}{s}:{s} {s}T{s} = .{{}}{s};{s}{s}`{s} over {s}`{s}{s}const{s} {s} = {s}T{s}{{}}{s};{s}{s}`{s}", .{ d, r, m, r, context, d, r, c, r, d, r, d, r, d, r, m, r, context, c, r, d, r, d, r }),
            .Z005 => try writer.print("type function {s}'{s}'{s} should be PascalCase", .{ y, context, r }),
            .Z006 => try writer.print("variable {s}'{s}'{s} should be snake_case", .{ y, context, r }),
            .Z007 => try writer.print("duplicate import {s}'{s}'{s}", .{ y, context, r }),
            .Z008 => try writer.writeAll("comment divider line"),
            .Z009 => try writer.print("file {s}'{s}'{s} has top-level fields and should be PascalCase", .{ y, context, r }),
            // syntax highlight: .{...} over Type{...}
            // context is "preferred\x00original" format
            .Z010 => {
                const sep = std.mem.indexOfScalar(u8, context, 0) orelse context.len;
                const preferred = context[0..sep];
                const original = if (sep < context.len) context[sep + 1 ..] else context;
                try writer.print("prefer {s}`{s}", .{ d, r });
                try writeHighlightedStructInit(writer, preferred, c, d, r);
                try writer.print("{s}`{s} over {s}`{s}", .{ d, r, d, r });
                try writeHighlightedStructInit(writer, original, c, d, r);
                try writer.print("{s}`{s}", .{ d, r });
            },
            .Z011 => try writer.print("{s}", .{context}),
            .Z012 => try writer.print("public function exposes private type {s}'{s}'{s}", .{ y, context, r }),
            .Z013 => try writer.print("unused import {s}'{s}'{s}", .{ y, context, r }),
            .Z014 => try writer.print("error set {s}'{s}'{s} should be PascalCase", .{ y, context, r }),
            .Z015 => try writer.print("public function exposes private error set {s}'{s}'{s}", .{ y, context, r }),
        }
    }
};

const std = @import("std");

fn writeHighlightedStructInit(writer: *std.Io.Writer, code: []const u8, cyan: []const u8, dim: []const u8, reset: []const u8) !void {
    const yellow = "\x1b[33m";
    // Handle truncated case: "Type{" -> "Type{...}"
    const is_truncated = std.mem.endsWith(u8, code, "{");

    var i: usize = 0;
    var after_dot = false;
    var after_eq = false;
    var in_braces = false;

    while (i < code.len) {
        const c = code[i];
        if (c == '{') {
            try writer.print("{s}{c}{s}", .{ dim, c, reset });
            in_braces = true;
            i += 1;
        } else if (c == '}') {
            try writer.print("{s}{c}{s}", .{ dim, c, reset });
            i += 1;
        } else if (c == '.') {
            try writer.print("{s}{c}{s}", .{ dim, c, reset });
            after_dot = true;
            after_eq = false;
            i += 1;
        } else if (c == '=') {
            try writer.print("{s}{c}{s}", .{ dim, c, reset });
            after_eq = true;
            after_dot = false;
            i += 1;
        } else if (c == ',') {
            try writer.print("{s}{c}{s}", .{ dim, c, reset });
            after_eq = false;
            after_dot = false;
            i += 1;
        } else if (c == ' ') {
            try writer.writeByte(' ');
            i += 1;
        } else {
            // Find end of identifier/value
            const start = i;
            while (i < code.len and code[i] != '{' and code[i] != '}' and code[i] != '.' and code[i] != ',' and code[i] != '=' and code[i] != ' ') : (i += 1) {}
            const token = code[start..i];
            if (!in_braces) {
                // Type name before { - cyan
                try writer.print("{s}{s}{s}", .{ cyan, token, reset });
            } else if (after_dot) {
                // Field name after . - yellow
                try writer.print("{s}{s}{s}", .{ yellow, token, reset });
            } else {
                // Value after = - no color
                try writer.writeAll(token);
            }
            after_dot = false;
        }
    }

    if (is_truncated) {
        try writer.print("{s}...}}{s}", .{ dim, reset });
    }
}

test "rule codes" {
    try std.testing.expectEqualStrings("Z001", Rule.Z001.code());
}
