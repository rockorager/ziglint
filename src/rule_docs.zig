//! Rule documentation embedded from `src/docs/rules/*.md` at compile time.
//!
//! The markdown files live inside the module root, so `@embedFile` reaches them
//! without extra build wiring. A rule without a documentation file fails to
//! compile: the enum in `rules.zig` and the docs directory cannot drift apart.
//!
//! The frontmatter is parsed here rather than at build time so the doc tests and
//! the `--explain` output read the same fields.

const std = @import("std");

pub const Frontmatter = struct {
    rule: ?[]const u8 = null,
    title: []const u8 = "",
    enabled: ?bool = null,
};

/// Returns the embedded documentation for a rule code, e.g. `Z024`.
pub fn get(comptime code: []const u8) []const u8 {
    return @embedFile("docs/rules/" ++ code ++ ".md");
}

/// Path of the documentation file, for error messages.
pub fn path(comptime code: []const u8) []const u8 {
    return "src/docs/rules/" ++ code ++ ".md";
}

fn frontmatterBlock(raw: []const u8) ?[]const u8 {
    if (!std.mem.startsWith(u8, raw, "---\n")) return null;
    const end = std.mem.find(u8, raw[4..], "\n---") orelse return null;
    return raw[4..][0..end];
}

pub fn parseFrontmatter(raw: []const u8) Frontmatter {
    var meta: Frontmatter = .{};
    const block = frontmatterBlock(raw) orelse return meta;

    var lines = std.mem.splitScalar(u8, block, '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "rule: ")) {
            meta.rule = std.mem.trim(u8, line[6..], " ");
        } else if (std.mem.startsWith(u8, line, "title: ")) {
            meta.title = std.mem.trim(u8, line[7..], " ");
        } else if (std.mem.eql(u8, line, "enabled: true")) {
            meta.enabled = true;
        } else if (std.mem.eql(u8, line, "enabled: false")) {
            meta.enabled = false;
        }
    }

    return meta;
}

/// Writes the documentation body for terminal display.
///
/// Drops the frontmatter, the leading title heading (the caller prints its own
/// header), and `// expect:` annotations, which exist only for the doc tests.
pub fn writeBody(writer: *std.Io.Writer, raw: []const u8) !void {
    var body = raw;
    if (frontmatterBlock(raw)) |block| {
        // Skip "---\n", the frontmatter, and the closing "\n---".
        body = raw[4 + block.len + 4 ..];
    }
    body = std.mem.trim(u8, body, "\r\n");

    var lines = std.mem.splitScalar(u8, body, '\n');
    var started = false;
    while (lines.next()) |line| {
        if (!started) {
            // Skip blank lines and the title heading: the caller prints its own
            // header, so repeating the heading here would duplicate it.
            if (line.len == 0) continue;
            if (std.mem.startsWith(u8, line, "# ")) continue;
            started = true;
        }
        // Test metadata, not documentation.
        const trimmed = std.mem.trimStart(u8, line, " ");
        if (std.mem.startsWith(u8, trimmed, "// expect:")) continue;
        try writer.print("{s}\n", .{line});
    }
}

test "parseFrontmatter reads rule, title, enabled" {
    const meta = parseFrontmatter(
        \\---
        \\rule: Z024
        \\title: Line exceeds maximum length
        \\enabled: false
        \\---
        \\
        \\# Z024
    );
    try std.testing.expectEqualStrings("Z024", meta.rule.?);
    try std.testing.expectEqualStrings("Line exceeds maximum length", meta.title);
    try std.testing.expectEqual(false, meta.enabled.?);
}

test "writeBody drops frontmatter, heading, and expect annotations" {
    var buf: [512]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buf);

    try writeBody(&writer,
        \\---
        \\rule: Z024
        \\title: Line exceeds maximum length
        \\enabled: true
        \\---
        \\
        \\# Z024: Line exceeds maximum length
        \\
        \\Detects long lines.
        \\
        \\```zig
        \\// expect: Z024
        \\const x = 1;
        \\```
    );

    try std.testing.expectEqualStrings(
        \\Detects long lines.
        \\
        \\```zig
        \\const x = 1;
        \\```
        \\
    , writer.buffered());
}
