//! Executable documentation tests.
//!
//! Parses the embedded rule documentation and validates that code examples
//! produce the expected linter diagnostics. Similar to Go's example tests.
//!
//! Code blocks with `// expect: Z001` comments should trigger that rule.
//! Code blocks without expect comments should produce no diagnostics.

const std = @import("std");
const Linter = @import("Linter.zig");
const ModuleGraph = @import("ModuleGraph.zig");
const TypeResolver = @import("TypeResolver.zig");
const rules = @import("rules.zig");
const rule_docs = @import("rule_docs.zig");

const DocTest = struct {
    code: []const u8,
    expected_rules: []const rules.Rule,
    compile_probe: ?[]const u8,
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
        if (std.mem.find(u8, content[4..], "\n---")) |end| {
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
    while (std.mem.findPos(u8, content, pos, "```zig\n")) |start| {
        // Count lines up to this point
        for (content[pos..start]) |c| {
            if (c == '\n') line_num += 1;
        }
        line_num += 1; // for the ```zig line

        const code_start = start + 7;
        if (std.mem.findPos(u8, content, code_start, "\n```")) |end| {
            const code = content[code_start..end];

            // Parse expected rules from `// expect: ZXXX` comments
            var expected: std.ArrayList(rules.Rule) = .empty;
            var code_lines = std.mem.splitScalar(u8, code, '\n');
            while (code_lines.next()) |code_line| {
                if (std.mem.find(u8, code_line, "// expect:")) |expect_pos| {
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

            const after_block = content[end + 4 ..];
            const probe_prefix = "\n<!-- compile-test: ";
            const compile_probe = if (std.mem.startsWith(u8, after_block, probe_prefix)) probe: {
                const probe_start = probe_prefix.len;
                const probe_end = std.mem.find(u8, after_block[probe_start..], " -->") orelse break :probe null;
                break :probe after_block[probe_start..][0..probe_end];
            } else null;

            try tests.append(allocator, .{
                .code = code,
                .expected_rules = try expected.toOwnedSlice(allocator),
                .compile_probe = compile_probe,
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
    try tmp_dir.dir.writeFile(std.testing.io, .{ .sub_path = "doc_test.zig", .data = source });
    const path = try tmp_dir.dir.realPathFileAlloc(std.testing.io, "doc_test.zig", allocator);
    defer allocator.free(path);

    // Try to create ModuleGraph for semantic analysis (may fail for invalid code)
    var graph: ?ModuleGraph = ModuleGraph.init(allocator, std.testing.io, path, null) catch null;
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

    if (doc_test.compile_probe) |probe| {
        const compile_source = try std.fmt.allocPrint(allocator,
            \\{s}
            \\
            \\comptime {{
            \\    {s}
            \\}}
        , .{ doc_test.code, probe });
        defer allocator.free(compile_source);
        try tmp_dir.dir.writeFile(std.testing.io, .{ .sub_path = "doc_test.zig", .data = compile_source });

        try tmp_dir.dir.createDirPath(std.testing.io, "zig-cache");
        const cache_path = try tmp_dir.dir.realPathFileAlloc(std.testing.io, "zig-cache", allocator);
        defer allocator.free(cache_path);

        const result = try std.process.run(allocator, std.testing.io, .{
            .argv = &.{ "zig", "test", path, "--cache-dir", cache_path },
            .stderr_limit = .limited(1024 * 1024),
            .stdout_limit = .limited(1024 * 1024),
        });
        defer allocator.free(result.stdout);
        defer allocator.free(result.stderr);

        const compiled = switch (result.term) {
            .exited => |code| code == 0,
            else => false,
        };
        if (!compiled) {
            std.debug.print("\n{s}:{d}: documented replacement does not compile\n", .{
                doc_path,
                doc_test.line_in_doc,
            });
            std.debug.print("Compiler output:\n{s}{s}\n", .{ result.stdout, result.stderr });
            return error.DocumentedReplacementDoesNotCompile;
        }
    }
}

pub fn runAllDocTests(allocator: std.mem.Allocator) !void {
    // Create temp directory for semantic analysis
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    // Docs are embedded at compile time, so a rule without a doc file fails the
    // build and no doc can be skipped at test time.
    inline for (std.meta.fields(rules.Rule)) |field| {
        const doc = try parseMarkdown(allocator, rule_docs.get(field.name));
        defer {
            for (doc.tests) |t| allocator.free(t.expected_rules);
            allocator.free(doc.tests);
        }

        for (doc.tests) |doc_test| {
            try runDocTest(allocator, rule_docs.path(field.name), doc_test, &tmp_dir);
        }
    }
}

test "parse compile test probe" {
    const doc = try parseMarkdown(std.testing.allocator,
        \\```zig
        \\fn example() void {}
        \\```
        \\<!-- compile-test: example(); -->
    );
    defer {
        for (doc.tests) |doc_test| std.testing.allocator.free(doc_test.expected_rules);
        std.testing.allocator.free(doc.tests);
    }

    try std.testing.expectEqual(1, doc.tests.len);
    try std.testing.expectEqualStrings("example();", doc.tests[0].compile_probe.?);
}

test "doc tests" {
    try runAllDocTests(std.testing.allocator);
}
