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

    pub fn code(self: Rule) []const u8 {
        return @tagName(self);
    }

    pub fn writeMessage(self: Rule, writer: *std.Io.Writer, context: []const u8) !void {
        switch (self) {
            .Z001 => try writer.print("function '{s}' should be camelCase", .{context}),
            .Z002 => try writer.print("variable '{s}' is unused but has a value", .{context}),
            .Z003 => try writer.writeAll("parse error"),
            .Z004 => try writer.print("prefer 'const {s}: T = .{{}}' over 'const {s} = T{{}}'", .{ context, context }),
            .Z005 => try writer.print("type function '{s}' should be PascalCase", .{context}),
            .Z006 => try writer.print("variable '{s}' should be snake_case", .{context}),
            .Z007 => try writer.print("duplicate import '{s}'", .{context}),
            .Z008 => try writer.writeAll("comment divider line"),
            .Z009 => try writer.print("file '{s}' has top-level fields and should be PascalCase", .{context}),
            .Z010 => try writer.print("redundant type specifier; prefer '.{s}' over explicit type", .{context}),
            .Z011 => try writer.print("{s}", .{context}),
        }
    }
};

const std = @import("std");

test "rule codes" {
    try std.testing.expectEqualStrings("Z001", Rule.Z001.code());
}
