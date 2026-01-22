//! Lint rule definitions with unique identifiers.

pub const Rule = enum(u16) {
    Z001 = 1,
    Z002 = 2,
    Z003 = 3,
    Z004 = 4,
    Z005 = 5,
    Z006 = 6,

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
        }
    }
};

const std = @import("std");

test "rule codes" {
    try std.testing.expectEqualStrings("Z001", Rule.Z001.code());
}
