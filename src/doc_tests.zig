//! Executable documentation tests.
//!
//! Parses markdown files in docs/rules/ and validates that code examples
//! produce the expected linter diagnostics. Similar to Go's example tests.
//!
//! Code blocks with `// expect: Z001` comments should trigger that rule.
//! Code blocks without expect comments should produce no diagnostics.

const std = @import("std");
const Linter = @import("Linter.zig");
const ModuleGraph = @import("ModuleGraph.zig");
const TypeResolver = @import("TypeResolver.zig");
const rules = @import("rules.zig");

const DocTest = struct {
    code: []const u8,
    expected_rules: []const rules.Rule,
    line_in_doc: usize,
};

const ParsedDoc = struct {
    rule: ?rules.Rule,
    tests: []const DocTest,
};

/// Parses a markdown file and extracts code blocks with their expectations.
fn parseMarkdown(allocator: std.mem.Allocator, content: []const u8) !ParsedDoc {
    var tests: std.ArrayList(DocTest) = .empty;
    var rule: ?rules.Rule = null;

    // Parse frontmatter for rule identifier
    if (std.mem.startsWith(u8, content, "---\n")) {
        if (std.mem.indexOf(u8, content[4..], "\n---")) |end| {
            const frontmatter = content[4..][0..end];
            var lines = std.mem.splitScalar(u8, frontmatter, '\n');
            while (lines.next()) |line| {
                if (std.mem.startsWith(u8, line, "rule: ")) {
                    const rule_code = line[6..];
                    rule = std.meta.stringToEnum(rules.Rule, rule_code);
                }
            }
        }
    }

    // Find all zig code blocks
    var line_num: usize = 1;
    var pos: usize = 0;
    while (std.mem.indexOfPos(u8, content, pos, "```zig\n")) |start| {
        // Count lines up to this point
        for (content[pos..start]) |c| {
            if (c == '\n') line_num += 1;
        }
        line_num += 1; // for the ```zig line

        const code_start = start + 7;
        if (std.mem.indexOfPos(u8, content, code_start, "\n```")) |end| {
            const code = content[code_start..end];

            // Parse expected rules from `// expect: ZXXX` comments
            var expected: std.ArrayList(rules.Rule) = .empty;
            var code_lines = std.mem.splitScalar(u8, code, '\n');
            while (code_lines.next()) |code_line| {
                if (std.mem.indexOf(u8, code_line, "// expect:")) |expect_pos| {
                    var expect_str = code_line[expect_pos + 10 ..];
                    expect_str = std.mem.trim(u8, expect_str, " ");
                    // Handle multiple expectations: `// expect: Z001, Z002`
                    var expects = std.mem.splitSequence(u8, expect_str, ",");
                    while (expects.next()) |e| {
                        const trimmed = std.mem.trim(u8, e, " ");
                        if (std.meta.stringToEnum(rules.Rule, trimmed)) |r| {
                            try expected.append(allocator, r);
                        }
                    }
                }
            }

            try tests.append(allocator, .{
                .code = code,
                .expected_rules = try expected.toOwnedSlice(allocator),
                .line_in_doc = line_num,
            });

            pos = end + 4;
        } else {
            break;
        }
    }

    return .{
        .rule = rule,
        .tests = try tests.toOwnedSlice(allocator),
    };
}

fn runDocTest(allocator: std.mem.Allocator, doc_path: []const u8, doc_test: DocTest, tmp_dir: *std.testing.TmpDir) !void {
    // Linter expects sentinel-terminated source
    const source = try allocator.allocSentinel(u8, doc_test.code.len, 0);
    defer allocator.free(source);
    @memcpy(source, doc_test.code);

    // Write to temp file for semantic analysis
    try tmp_dir.dir.writeFile(.{ .sub_path = "doc_test.zig", .data = source });
    const path = try tmp_dir.dir.realpathAlloc(allocator, "doc_test.zig");
    defer allocator.free(path);

    // Try to create ModuleGraph for semantic analysis (may fail for invalid code)
    var graph: ?ModuleGraph = ModuleGraph.init(allocator, path, null) catch null;
    defer if (graph) |*g| g.deinit();

    var resolver: ?TypeResolver = if (graph) |*g| TypeResolver.init(allocator, g) else null;
    defer if (resolver) |*r| r.deinit();

    var linter: Linter = if (resolver) |*r|
        .initWithSemantics(allocator, source, path, r, path, null)
    else
        .init(allocator, source, path, null);
    defer linter.deinit();
    linter.lint();

    // Check expected rules
    for (doc_test.expected_rules) |expected_rule| {
        const count = linter.diagnosticCount(expected_rule);
        if (count == 0) {
            std.debug.print("\n{s}:{d}: expected {s} but got no diagnostic\n", .{
                doc_path,
                doc_test.line_in_doc,
                expected_rule.code(),
            });
            std.debug.print("Code:\n{s}\n", .{doc_test.code});
            return error.MissingExpectedDiagnostic;
        }
    }

    // If no expectations, should have no diagnostics
    if (doc_test.expected_rules.len == 0) {
        const total = linter.diagnostics.items.len;
        if (total > 0) {
            std.debug.print("\n{s}:{d}: expected no diagnostics but got {d}\n", .{
                doc_path,
                doc_test.line_in_doc,
                total,
            });
            std.debug.print("Code:\n{s}\n", .{doc_test.code});
            for (linter.diagnostics.items) |d| {
                std.debug.print("  - {s}: {s}\n", .{ d.rule.code(), d.context });
            }
            return error.UnexpectedDiagnostic;
        }
    }
}

pub fn runAllDocTests(allocator: std.mem.Allocator) !void {
    // Open docs/rules directory
    const docs_path = "docs/rules";
    var dir = std.fs.cwd().openDir(docs_path, .{ .iterate = true }) catch |err| {
        if (err == error.FileNotFound) {
            std.debug.print("No docs/rules directory found, skipping doc tests\n", .{});
            return;
        }
        return err;
    };
    defer dir.close();

    // Create temp directory for semantic analysis
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    var file_count: usize = 0;
    var test_count: usize = 0;
    var iter = dir.iterate();
    while (try iter.next()) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.name, ".md")) continue;

        const file = try dir.openFile(entry.name, .{});
        defer file.close();

        const content = try file.readToEndAlloc(allocator, 1024 * 1024);
        defer allocator.free(content);

        const doc = try parseMarkdown(allocator, content);
        defer {
            for (doc.tests) |t| allocator.free(t.expected_rules);
            allocator.free(doc.tests);
        }

        const full_path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ docs_path, entry.name });
        defer allocator.free(full_path);

        for (doc.tests) |doc_test| {
            try runDocTest(allocator, full_path, doc_test, &tmp_dir);
            test_count += 1;
        }
        file_count += 1;
    }

    if (file_count > 0) {
        std.debug.print("doc tests: {d} examples from {d} files passed\n", .{ test_count, file_count });
    }
}

test "doc tests" {
    try runAllDocTests(std.testing.allocator);
}
