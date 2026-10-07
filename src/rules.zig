//! Lint rule definitions with unique identifiers.

const std = @import("std");

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
    Z023 = 23,
    Z024 = 24,
    Z025 = 25,
    Z026 = 26,
    Z027 = 27,
    Z028 = 28,
    Z029 = 29,
    Z030 = 30,
    Z031 = 31,
    Z032 = 32,
    Z033 = 33,

    /// Returns the config struct type for this rule.
    /// All config types have `enabled: bool` (default varies per rule).
    /// Some rules have additional fields (e.g., Z024 has max_length).
    fn ConfigType(comptime self: Rule) type {
        const DefaultConfig = RuleConfig(struct {}, true);
        const DisabledConfig = RuleConfig(struct {}, false);
        return switch (self) {
            .Z024 => RuleConfig(struct { max_length: u32 = 120 }, true),
            .Z033 => DisabledConfig, // Redundant type name words - disabled by default
            else => DefaultConfig,
        };
    }

    pub const Config = blk: {
        const enum_fields = @typeInfo(Rule).@"enum".fields;
        var field_names: [enum_fields.len][:0]const u8 = undefined;
        var field_types: [enum_fields.len]type = undefined;
        var field_attrs: [enum_fields.len]std.builtin.Type.StructField.Attributes = undefined;

        for (enum_fields, 0..) |field, i| {
            const rule: Rule = @enumFromInt(field.value);
            const ConfigT = rule.ConfigType();
            const default_value: ConfigT = .{};
            field_names[i] = field.name;
            field_types[i] = ConfigT;
            field_attrs[i] = .{
                .default_value_ptr = @ptrCast(&default_value),
            };
        }
        break :blk @Struct(.auto, null, &field_names, &field_types, &field_attrs);
    };

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
            .Z002 => try writer.print("initialized variable {s}'{s}'{s} uses a named discard; rename it if used or write {s}`_ = expression;`{s} to discard the value", .{ y, context, r, d, r }),
            .Z003 => {
                try writer.writeAll("parse error");
                if (context.len > 0) try writer.print(": {s}", .{context});
            },
            .Z004 => {
                const sep = std.mem.indexOfScalar(u8, context, 0) orelse context.len;
                const name = context[0..sep];
                const type_name = if (sep < context.len) context[sep + 1 ..] else "the explicit type";
                try writer.print("prefer type annotation {s}'{s}'{s} with an anonymous initializer for {s}'{s}'{s}; preserve the declaration kind, modifiers, and fields", .{
                    m, type_name, r, y, name, r,
                });
            },
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
            // return/try/const=purple, expr/value=yellow, punctuation=dim
            .Z017 => {
                try writer.print("avoid {s}try{s} in {s}return{s}; hoist it to preserve payload coercion: {s}`{s}{s}const{s} {s}value{s} = {s}try{s} {s}{s}{s}; {s}return{s} {s}value{s};{s}`{s}", .{
                    p, r, p, r, d, r, p, r, y, r, p, r, y, context, d, p, r, y, r, d, r,
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
            .Z020 => {
                if (context.len > 0) {
                    try writer.print("inline {s}@This(){s} in named struct; use {s}'{s}'{s} instead", .{ b, r, y, context, r });
                } else {
                    try writer.print("inline {s}@This(){s}; assign it to {s}`const Self = @This();`{s}", .{ b, r, d, r });
                }
            },
            // file-struct @This() alias should match filename
            // context is "alias\x00expected" format
            .Z021 => {
                const sep = std.mem.indexOfScalar(u8, context, 0) orelse context.len;
                const alias = context[0..sep];
                const expected = if (sep < context.len) context[sep + 1 ..] else context;
                try writer.print("{s}@This(){s} alias {s}'{s}'{s} should match filename {s}'{s}'{s} or be {s}'Self'{s}", .{ b, r, y, alias, r, y, expected, r, y, r });
            },
            // @This() alias in anonymous/local struct should be Self
            .Z022 => {
                try writer.print("{s}@This(){s} alias {s}'{s}'{s} should be {s}'Self'{s}", .{ b, r, y, context, r, y, r });
            },
            // argument order: type params, Allocator, Io, then other args
            // context is "current_kind\x00expected_before" format
            .Z023 => {
                const sep = std.mem.indexOfScalar(u8, context, 0) orelse context.len;
                const current = context[0..sep];
                const before = if (sep < context.len) context[sep + 1 ..] else "";
                try writer.print("{s}'{s}'{s} parameter should come before {s}'{s}'{s}", .{ y, current, r, y, before, r });
            },
            // line length exceeds limit
            // context is "actual_len\x00max_len" format
            .Z024 => {
                const sep = std.mem.indexOfScalar(u8, context, 0) orelse context.len;
                const actual = context[0..sep];
                const max = if (sep < context.len) context[sep + 1 ..] else "120";
                try writer.print("line exceeds {s}{s}{s} bytes ({s}{s}{s} bytes)", .{ y, max, r, y, actual, r });
            },
            // redundant catch: `catch |err| return err` -> use `try`
            // catch=purple, try=purple, expr=yellow, punctuation=dim
            .Z025 => {
                try writer.print("redundant {s}catch{s}: {s}`{s}{s}catch{s} {s}|{s}{s}{s}{s}| {s}{s}return{s} {s}{s}{s}`{s} -> use {s}try{s}", .{
                    p, r, d, r, p, r, d, r, y, context, d, r, p, r, y, context, d, r, p, r,
                });
            },
            // suppressed error: empty catch block swallows errors
            // catch=purple, punctuation=dim
            .Z026 => {
                try writer.print("empty {s}catch{s} block suppresses errors: {s}`{s}{s}catch{s} {s}{{}}{s}{s}`{s}", .{
                    p, r, d, r, p, r, d, r, d, r,
                });
            },
            // instance.decl -> Type.decl
            // context is "field_name\x00type_name"
            .Z027 => {
                const sep = std.mem.indexOfScalar(u8, context, 0) orelse context.len;
                const field = context[0..sep];
                const type_name = if (sep < context.len) context[sep + 1 ..] else "";
                try writer.print("access {s}'{s}'{s} through type {s}'{s}'{s} instead of instance", .{
                    y, field, r, m, type_name, r,
                });
            },
            .Z028 => {
                try writer.print("inline {s}@import{s}; assign to a top-level {s}const{s}", .{ b, r, p, r });
            },
            .Z029 => {
                try writer.print("redundant {s}@as{s}{s}({s}{s}{s}{s}, ...){s}: type {s}{s}{s} already known from context", .{
                    b, r, d, r, m, context, d, r, m, context, r,
                });
            },
            .Z030 => {
                const sep = std.mem.indexOfScalar(u8, context, 0) orelse context.len;
                const param_name = context[0..sep];
                const reason = if (sep < context.len) context[sep + 1 ..] else "";
                try writer.print("{s}deinit{s} should set {s}{s}.* = undefined{s}", .{ y, r, b, param_name, r });
                if (reason.len > 0) {
                    try writer.print(" ({s})", .{reason});
                }
            },
            .Z031 => {
                try writer.print("identifier {s}'{s}'{s} has underscore prefix; avoid {s}_like_this{s} naming", .{ y, context, r, y, r });
            },
            .Z032 => {
                // context is "name\x00suggestion"
                const sep = std.mem.indexOfScalar(u8, context, 0) orelse context.len;
                const name = context[0..sep];
                const suggestion = if (sep < context.len) context[sep + 1 ..] else "";
                if (suggestion.len > 0) {
                    try writer.print("acronym in {s}'{s}'{s} should use standard casing: {s}'{s}'{s}", .{ y, name, r, y, suggestion, r });
                } else {
                    try writer.print("acronym in {s}'{s}'{s} should use standard casing", .{ y, name, r });
                }
            },
            .Z033 => {
                // context is "name\x00word"
                const sep = std.mem.indexOfScalar(u8, context, 0) orelse context.len;
                const name = context[0..sep];
                const word = if (sep < context.len) context[sep + 1 ..] else "";
                try writer.print("type name {s}'{s}'{s} contains redundant word {s}'{s}'{s}", .{ y, name, r, y, word, r });
            },
        }
    }
};

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

/// Generates a config struct with `enabled: bool` plus any extra fields.
fn RuleConfig(comptime Extra: type, comptime enabled_by_default: bool) type {
    const extra_fields = @typeInfo(Extra).@"struct".fields;

    var field_names: [1 + extra_fields.len][:0]const u8 = undefined;
    var field_types: [1 + extra_fields.len]type = undefined;
    var field_attrs: [1 + extra_fields.len]std.builtin.Type.StructField.Attributes = undefined;

    const default_enabled: bool = enabled_by_default;
    field_names[0] = "enabled";
    field_types[0] = bool;
    field_attrs[0] = .{
        .default_value_ptr = @ptrCast(&default_enabled),
    };

    for (extra_fields, 0..) |f, i| {
        field_names[1 + i] = f.name;
        field_types[1 + i] = f.type;
        field_attrs[1 + i] = .{
            .@"comptime" = f.is_comptime,
            .@"align" = f.alignment,
            .default_value_ptr = f.default_value_ptr,
        };
    }

    return @Struct(.auto, null, &field_names, &field_types, &field_attrs);
}

test "rule codes" {
    try std.testing.expectEqualStrings("Z001", Rule.Z001.code());
}

test "Z017 recommends a coercion-preserving rewrite" {
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();

    try Rule.Z017.writeMessage(&output.writer, "allocThing()", false);

    try std.testing.expectEqualStrings(
        "avoid try in return; hoist it to preserve payload coercion: `const value = try allocThing(); return value;`",
        output.written(),
    );
}

test "Z002 recommends valid fixes for named discards" {
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();

    try Rule.Z002.writeMessage(&output.writer, "_result", false);

    try std.testing.expectEqualStrings(
        "initialized variable '_result' uses a named discard; rename it if used or write `_ = expression;` to discard the value",
        output.written(),
    );
}

test "Z003 includes the parser error" {
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();

    try Rule.Z003.writeMessage(&output.writer, "expected expression", false);

    try std.testing.expectEqualStrings("parse error: expected expression", output.written());
}

test "Z004 recommends preserving the declaration" {
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();

    try Rule.Z004.writeMessage(&output.writer, "point\x00Point", false);

    try std.testing.expectEqualStrings(
        "prefer type annotation 'Point' with an anonymous initializer for 'point'; preserve the declaration kind, modifiers, and fields",
        output.written(),
    );
}

test "Z020 recommends the enclosing named struct" {
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();

    try Rule.Z020.writeMessage(&output.writer, "Widget", false);

    try std.testing.expectEqualStrings("inline @This() in named struct; use 'Widget' instead", output.written());
}

test "Z020 recommends Self for an anonymous struct" {
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();

    try Rule.Z020.writeMessage(&output.writer, "", false);

    try std.testing.expectEqualStrings("inline @This(); assign it to `const Self = @This();`", output.written());
}

test "Z021 includes both accepted aliases" {
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();

    try Rule.Z021.writeMessage(&output.writer, "Wrong\x00Config", false);

    try std.testing.expectEqualStrings(
        "@This() alias 'Wrong' should match filename 'Config' or be 'Self'",
        output.written(),
    );
}

test "Z030 uses the receiver name" {
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();

    try Rule.Z030.writeMessage(&output.writer, "value\x00has early return before invalidation", false);

    try std.testing.expectEqualStrings(
        "deinit should set value.* = undefined (has early return before invalidation)",
        output.written(),
    );
}
