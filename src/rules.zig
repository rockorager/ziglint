//! Lint rule definitions with unique identifiers.

pub const Rule = enum(u16) {
    Z001 = 1,
    Z002 = 2,
    Z003 = 3,
    Z004 = 4,
    Z005 = 5,
    Z006 = 6,
    Z007 = 7,
    Z009 = 9,
    Z010 = 10,
    Z011 = 11,
    Z012 = 12,
    Z013 = 13,
    Z014 = 14,
    Z015 = 15,
    Z016 = 16,
    Z017 = 17,
    Z018 = 18,
    Z019 = 19,
    Z020 = 20,
    Z021 = 21,
    Z022 = 22,
    Z025 = 25,

    pub fn code(self: Rule) []const u8 {
        return @tagName(self);
    }

    // ANSI escape codes
    const blue = "\x1b[34m";
    const yellow = "\x1b[33m";
    const magenta = "\x1b[35m";
    const purple = "\x1b[35m";
    const dim = "\x1b[2m";
    const reset = "\x1b[0m";

    pub fn writeMessage(self: Rule, writer: *std.Io.Writer, context: []const u8, use_color: bool) !void {
        const b = if (use_color) blue else "";
        const y = if (use_color) yellow else "";
        const m = if (use_color) magenta else "";
        const p = if (use_color) purple else "";
        const d = if (use_color) dim else "";
        const r = if (use_color) reset else "";

        switch (self) {
            .Z001 => try writer.print("function {s}'{s}'{s} should be camelCase", .{ y, context, r }),
            .Z002 => try writer.print("variable {s}'{s}'{s} is unused but has a value", .{ y, context, r }),
            .Z003 => try writer.writeAll("parse error"),
            // syntax highlight: `const name: T = .{};` vs `const name = T{};`
            // const=purple (keyword), name=yellow (identifier), T=magenta (type)
            .Z004 => try writer.print("prefer {s}`{s}{s}const{s} {s}{s}:{s} {s}T{s} = .{{}}{s};{s}{s}`{s} over {s}`{s}{s}const{s} {s} = {s}T{s}{{}}{s};{s}{s}`{s}", .{ d, r, p, r, context, d, r, m, r, d, r, d, r, d, r, p, r, context, m, r, d, r, d, r }),
            .Z005 => try writer.print("type function {s}'{s}'{s} should be PascalCase", .{ y, context, r }),
            .Z006 => try writer.print("variable {s}'{s}'{s} should be snake_case", .{ y, context, r }),
            .Z007 => try writer.print("duplicate import {s}'{s}'{s}", .{ y, context, r }),
            .Z009 => try writer.print("file {s}'{s}'{s} has top-level fields and should be PascalCase", .{ y, context, r }),
            // syntax highlight: .{...} over Type{...}
            // context is "preferred\x00original" format
            .Z010 => {
                const sep = std.mem.indexOfScalar(u8, context, 0) orelse context.len;
                const preferred = context[0..sep];
                const original = if (sep < context.len) context[sep + 1 ..] else context;
                try writer.print("prefer {s}`{s}", .{ d, r });
                try writeHighlightedStructInit(writer, preferred, m, d, r);
                try writer.print("{s}`{s} over {s}`{s}", .{ d, r, d, r });
                try writeHighlightedStructInit(writer, original, m, d, r);
                try writer.print("{s}`{s}", .{ d, r });
            },
            .Z011 => try writer.print("{s}", .{context}),
            .Z012 => try writer.print("public function exposes private type {s}'{s}'{s}", .{ y, context, r }),
            .Z013 => try writer.print("unused import {s}'{s}'{s}", .{ y, context, r }),
            .Z014 => try writer.print("error set {s}'{s}'{s} should be PascalCase", .{ y, context, r }),
            .Z015 => try writer.print("public function exposes private error set {s}'{s}'{s}", .{ y, context, r }),
            .Z016 => {
                // assert=blue, and/or=purple, a/b=yellow, punctuation=dim
                // `assert(a and b)` -> `assert(a); assert(b);`
                try writer.print("split compound assert: {s}`{s}{s}assert{s}{s}({s}{s}a{s} {s}{s}{s} {s}b{s}{s})`{s}", .{
                    d, r, b, r, d, r, y, r, p, context, r, y, r, d, r,
                });
                try writer.print(" -> {s}`{s}{s}assert{s}{s}({s}{s}a{s}{s}); {s}{s}assert{s}{s}({s}{s}b{s}{s});`{s}", .{
                    d, r, b, r, d, r, y, r, d, r, b, r, d, r, y, r, d, r,
                });
            },
            // return=purple, try=purple, expr=yellow, punctuation=dim
            // `return try expr` -> `return expr`
            .Z017 => {
                // redundant `try` in `return`: `return try expr` -> `return expr`
                try writer.print("redundant {s}try{s} in {s}return{s}: {s}`{s}return try {s}{s}{s}`{s} -> {s}`{s}return {s}{s}{s}`{s}", .{
                    p, r, p, r, d, r, y, context, d, r, d, r, y, context, d, r,
                });
            },
            // redundant @as when type is already known from context
            // context is type name
            .Z018 => {
                try writer.print("redundant {s}@as{s}{s}({s}{s}{s}{s}, ...){s}: type {s}{s}{s} already known from context", .{
                    b, r, d, r, m, context, d, r, m, context, r,
                });
            },
            // @This() in named struct - use the type name
            .Z019 => {
                try writer.print("{s}@This(){s} used in named struct; use {s}'{s}'{s} instead", .{ b, r, y, context, r });
            },
            // inline @This() - assign to a constant
            .Z020 => {
                try writer.print("{s}@This(){s} should be assigned to a constant", .{ b, r });
            },
            // file-struct @This() alias should match filename
            // context is "alias\x00expected" format
            .Z021 => {
                const sep = std.mem.indexOfScalar(u8, context, 0) orelse context.len;
                const alias = context[0..sep];
                const expected = if (sep < context.len) context[sep + 1 ..] else context;
                try writer.print("{s}@This(){s} alias {s}'{s}'{s} should match filename {s}'{s}'{s}", .{ b, r, y, alias, r, y, expected, r });
            },
            // @This() alias in anonymous/local struct should be Self
            .Z022 => {
                try writer.print("{s}@This(){s} alias {s}'{s}'{s} should be {s}'Self'{s}", .{ b, r, y, context, r, y, r });
            },
            // missing @alignCast
            .Z025 => {
                // @ptrCast=blue, @alignCast=blue
                try writer.print("{s}@ptrCast{s} without {s}@alignCast{s} may cause alignment violations", .{ b, r, b, r });
            },
        }
    }
};

const std = @import("std");

fn writeHighlightedStructInit(writer: *std.Io.Writer, code: []const u8, type_color: []const u8, dim: []const u8, reset: []const u8) !void {
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
                // Type name before { - magenta
                try writer.print("{s}{s}{s}", .{ type_color, token, reset });
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
