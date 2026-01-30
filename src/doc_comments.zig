//! Doc comment extraction for semantic analysis.
//!
//! Extracts doc comments (///) from above function and method definitions.

const std = @import("std");
const Ast = std.zig.Ast;
const Token = std.zig.Token;

/// Extracts the doc comment text for a given AST node.
/// Returns null if no doc comment is present.
/// The returned slice references memory owned by the allocator.
pub fn getDocComment(allocator: std.mem.Allocator, tree: *const Ast, node: Ast.Node.Index) ?[]const u8 {
    const first_token = tree.firstToken(node);
    if (first_token == 0) return null;

    // Walk backwards from the first token to find doc comments
    var doc_tokens: std.ArrayList(Ast.TokenIndex) = .empty;
    defer doc_tokens.deinit(allocator);

    var token = first_token - 1;
    while (true) {
        const tag = tree.tokenTag(token);
        if (tag == .doc_comment) {
            doc_tokens.append(allocator, token) catch return null;
        } else {
            // Stop at non-doc-comment tokens (skip pub keyword)
            if (tag != .keyword_pub) break;
        }
        if (token == 0) break;
        token -= 1;
    }

    if (doc_tokens.items.len == 0) return null;

    // Reverse to get chronological order
    std.mem.reverse(Ast.TokenIndex, doc_tokens.items);

    // Build the combined doc comment text
    var result: std.ArrayList(u8) = .empty;
    errdefer result.deinit(allocator);

    for (doc_tokens.items, 0..) |doc_token, i| {
        if (i > 0) result.append(allocator, '\n') catch return null;

        const slice = tree.tokenSlice(doc_token);
        // Strip "/// " or "///" prefix
        const content = if (std.mem.startsWith(u8, slice, "/// "))
            slice[4..]
        else if (std.mem.startsWith(u8, slice, "///"))
            slice[3..]
        else
            slice;

        result.appendSlice(allocator, content) catch return null;
    }

    return result.toOwnedSlice(allocator) catch null;
}

test "extract single line doc comment" {
    const source =
        \\/// This is a doc comment
        \\fn foo() void {}
    ;

    var tree = try Ast.parse(std.testing.allocator, source, .zig);
    defer tree.deinit(std.testing.allocator);

    const root_decls = tree.rootDecls();
    try std.testing.expect(root_decls.len > 0);

    const doc = getDocComment(std.testing.allocator, &tree, root_decls[0]);
    defer if (doc) |d| std.testing.allocator.free(d);

    try std.testing.expect(doc != null);
    try std.testing.expectEqualStrings("This is a doc comment", doc.?);
}

test "extract multi-line doc comment" {
    const source =
        \\/// First line
        \\/// Second line
        \\/// Third line
        \\fn foo() void {}
    ;

    var tree = try Ast.parse(std.testing.allocator, source, .zig);
    defer tree.deinit(std.testing.allocator);

    const root_decls = tree.rootDecls();
    const doc = getDocComment(std.testing.allocator, &tree, root_decls[0]);
    defer if (doc) |d| std.testing.allocator.free(d);

    try std.testing.expect(doc != null);
    try std.testing.expectEqualStrings("First line\nSecond line\nThird line", doc.?);
}

test "no doc comment returns null" {
    const source = "fn foo() void {}";

    var tree = try Ast.parse(std.testing.allocator, source, .zig);
    defer tree.deinit(std.testing.allocator);

    const root_decls = tree.rootDecls();
    const doc = getDocComment(std.testing.allocator, &tree, root_decls[0]);

    try std.testing.expect(doc == null);
}

test "doc comment with pub function" {
    const source =
        \\/// Public function doc
        \\pub fn foo() void {}
    ;

    var tree = try Ast.parse(std.testing.allocator, source, .zig);
    defer tree.deinit(std.testing.allocator);

    const root_decls = tree.rootDecls();
    const doc = getDocComment(std.testing.allocator, &tree, root_decls[0]);
    defer if (doc) |d| std.testing.allocator.free(d);

    try std.testing.expect(doc != null);
    try std.testing.expectEqualStrings("Public function doc", doc.?);
}

test "doc comment without space after ///" {
    const source =
        \\///No space after slashes
        \\fn foo() void {}
    ;

    var tree = try Ast.parse(std.testing.allocator, source, .zig);
    defer tree.deinit(std.testing.allocator);

    const root_decls = tree.rootDecls();
    const doc = getDocComment(std.testing.allocator, &tree, root_decls[0]);
    defer if (doc) |d| std.testing.allocator.free(d);

    try std.testing.expect(doc != null);
    try std.testing.expectEqualStrings("No space after slashes", doc.?);
}
