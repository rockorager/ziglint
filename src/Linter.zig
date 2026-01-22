//! Core linter that parses Zig source and runs lint rules.

const std = @import("std");
const Ast = std.zig.Ast;
const rules = @import("rules.zig");

const Linter = @This();

allocator: std.mem.Allocator,
source: [:0]const u8,
path: []const u8,
tree: Ast,
diagnostics: std.ArrayListUnmanaged(Diagnostic),

pub const Diagnostic = struct {
    path: []const u8,
    line: u32,
    column: u32,
    rule: rules.Rule,
    context: []const u8 = "",

    pub fn write(self: Diagnostic, writer: *std.Io.Writer) !void {
        try writer.print("{s}: {s}:{}:{}: ", .{
            self.rule.code(),
            self.path,
            self.line,
            self.column,
        });
        try self.rule.writeMessage(writer, self.context);
        try writer.writeByte('\n');
    }
};

pub fn init(allocator: std.mem.Allocator, source: [:0]const u8, path: []const u8) Linter {
    return .{
        .allocator = allocator,
        .source = source,
        .path = path,
        .tree = Ast.parse(allocator, source, .zig) catch unreachable,
        .diagnostics = .empty,
    };
}

pub fn deinit(self: *Linter) void {
    self.tree.deinit(self.allocator);
    self.diagnostics.deinit(self.allocator);
}

pub fn lint(self: *Linter) void {
    self.checkParseErrors();
    if (self.tree.errors.len > 0) return;

    for (self.tree.rootDecls()) |node| {
        self.visitNode(node);
    }
}

fn checkParseErrors(self: *Linter) void {
    for (self.tree.errors) |err| {
        const loc = self.tree.tokenLocation(0, err.token);
        self.report(loc, .Z003, "");
    }
}

fn visitNode(self: *Linter, node: Ast.Node.Index) void {
    const tag = self.tree.nodeTag(node);

    switch (tag) {
        .fn_decl => self.checkFnDecl(node),
        .simple_var_decl, .aligned_var_decl, .local_var_decl, .global_var_decl => self.checkVarDecl(node),
        else => {},
    }

    self.visitChildren(node);
}

fn visitChildren(self: *Linter, node: Ast.Node.Index) void {
    const tag = self.tree.nodeTag(node);
    switch (tag) {
        .fn_decl => {
            const data = self.tree.nodeData(node).node_and_node;
            self.visitNode(data[0]);
            self.visitNode(data[1]);
        },
        .block, .block_semicolon => {
            var buf: [2]Ast.Node.Index = undefined;
            const stmts = self.tree.blockStatements(&buf, node) orelse return;
            for (stmts) |stmt| self.visitNode(stmt);
        },
        .block_two, .block_two_semicolon => {
            const data = self.tree.nodeData(node).opt_node_and_opt_node;
            if (data[0].unwrap()) |n| self.visitNode(n);
            if (data[1].unwrap()) |n| self.visitNode(n);
        },
        else => {},
    }
}

fn checkFnDecl(self: *Linter, node: Ast.Node.Index) void {
    var buf: [1]Ast.Node.Index = undefined;
    const fn_proto = self.tree.fullFnProto(&buf, node) orelse return;

    const name_token = fn_proto.name_token orelse return;
    const name = self.tree.tokenSlice(name_token);

    const returns_type = if (fn_proto.ast.return_type.unwrap()) |ret| blk: {
        break :blk self.tree.nodeTag(ret) == .identifier and
            std.mem.eql(u8, self.tree.tokenSlice(self.tree.nodeMainToken(ret)), "type");
    } else false;

    if (returns_type) {
        if (!isPascalCase(name)) {
            const loc = self.tree.tokenLocation(0, name_token);
            self.report(loc, .Z005, name);
        }
    } else {
        if (!isValidFunctionName(name)) {
            const loc = self.tree.tokenLocation(0, name_token);
            self.report(loc, .Z001, name);
        }
    }
}

fn checkVarDecl(self: *Linter, node: Ast.Node.Index) void {
    const var_decl = self.tree.fullVarDecl(node) orelse return;

    const name_token = var_decl.ast.mut_token + 1;
    const name = self.tree.tokenSlice(name_token);

    if (name.len > 0 and name[0] == '_' and name.len > 1 and name[1] != '_') {
        if (var_decl.ast.init_node != .none) {
            const loc = self.tree.tokenLocation(0, name_token);
            self.report(loc, .Z002, name);
        }
    }

    if (!isSnakeCase(name) and !isTypeAlias(self, var_decl)) {
        const loc = self.tree.tokenLocation(0, name_token);
        self.report(loc, .Z006, name);
    }

    if (var_decl.ast.type_node == .none) {
        if (var_decl.ast.init_node.unwrap()) |init_node| {
            if (isExplicitStructInit(self.tree.nodeTag(init_node))) {
                const loc = self.tree.tokenLocation(0, var_decl.ast.mut_token);
                self.report(loc, .Z004, name);
            }
        }
    }
}

fn isExplicitStructInit(tag: Ast.Node.Tag) bool {
    return switch (tag) {
        .struct_init,
        .struct_init_comma,
        .struct_init_one,
        .struct_init_one_comma,
        => true,
        else => false,
    };
}

fn isValidFunctionName(name: []const u8) bool {
    if (name.len == 0) return false;
    if (name[0] >= 'A' and name[0] <= 'Z') return false;
    if (name[0] == '_') return true;

    for (name) |c| {
        if (c == '_' and name.len > 1) {
            const has_upper = for (name) |ch| {
                if (ch >= 'A' and ch <= 'Z') break true;
            } else false;
            if (has_upper) return false;
        }
    }

    return true;
}

fn isPascalCase(name: []const u8) bool {
    if (name.len == 0) return false;
    if (name[0] < 'A' or name[0] > 'Z') return false;
    for (name) |c| {
        if (c == '_') return false;
    }
    return true;
}

fn isSnakeCase(name: []const u8) bool {
    if (name.len == 0) return false;
    if (name[0] == '_') return true;
    for (name) |c| {
        if (c >= 'A' and c <= 'Z') return false;
    }
    return true;
}

fn isTypeAlias(self: *Linter, var_decl: Ast.full.VarDecl) bool {
    const init_node = var_decl.ast.init_node.unwrap() orelse return false;
    const tag = self.tree.nodeTag(init_node);
    return switch (tag) {
        .identifier => blk: {
            const token = self.tree.tokenSlice(self.tree.nodeMainToken(init_node));
            break :blk std.mem.eql(u8, token, "type") or isPascalCase(token);
        },
        .field_access => blk: {
            const data = self.tree.nodeData(init_node).node_and_token;
            const field_name = self.tree.tokenSlice(data[1]);
            break :blk isPascalCase(field_name);
        },
        .builtin_call_two, .builtin_call_two_comma, .builtin_call, .builtin_call_comma => blk: {
            const token = self.tree.tokenSlice(self.tree.nodeMainToken(init_node));
            break :blk std.mem.eql(u8, token, "@This") or
                std.mem.eql(u8, token, "@import") or
                std.mem.eql(u8, token, "@Type");
        },
        .container_decl,
        .container_decl_trailing,
        .container_decl_two,
        .container_decl_two_trailing,
        .container_decl_arg,
        .container_decl_arg_trailing,
        .tagged_union,
        .tagged_union_trailing,
        .tagged_union_two,
        .tagged_union_two_trailing,
        .tagged_union_enum_tag,
        .tagged_union_enum_tag_trailing,
        => true,
        else => false,
    };
}

fn isIgnored(self: *Linter, line: usize, rule: rules.Rule) bool {
    // Check inline comment on current line
    if (self.lineHasIgnore(self.getLineText(line), rule)) return true;

    // Check preceding comment-only lines (walk back through consecutive comments)
    var check_line = line;
    while (check_line > 0) {
        check_line -= 1;
        const prev_line = self.getLineText(check_line);
        const trimmed = std.mem.trimLeft(u8, prev_line, " \t");
        if (!std.mem.startsWith(u8, trimmed, "//")) break;
        if (self.lineHasIgnore(prev_line, rule)) return true;
    }

    return false;
}

fn lineHasIgnore(_: *Linter, line_text: []const u8, rule: rules.Rule) bool {
    if (std.mem.indexOf(u8, line_text, "// ziglint-ignore:")) |idx| {
        const ignore_part = line_text[idx + 18 ..];
        if (std.mem.indexOf(u8, ignore_part, rule.code()) != null) return true;
    }
    return false;
}

fn getLineText(self: *Linter, line: usize) []const u8 {
    const line_start = if (line == 0) 0 else blk: {
        var newlines: usize = 0;
        for (self.source, 0..) |c, i| {
            if (c == '\n') {
                newlines += 1;
                if (newlines == line) break :blk i + 1;
            }
        }
        break :blk self.source.len;
    };

    const line_end = for (self.source[line_start..], line_start..) |c, i| {
        if (c == '\n') break i;
    } else self.source.len;

    return self.source[line_start..line_end];
}

fn report(self: *Linter, loc: Ast.Location, rule: rules.Rule, context: []const u8) void {
    if (self.isIgnored(loc.line, rule)) return;

    self.diagnostics.append(self.allocator, .{
        .path = self.path,
        .line = @intCast(loc.line + 1),
        .column = @intCast(loc.column + 1),
        .rule = rule,
        .context = context,
    }) catch {};
}

// =============================================================================
// Z001: function names should be camelCase
// =============================================================================

test "Z001: detect PascalCase function" {
    var linter: Linter = .init(std.testing.allocator, "fn MyFunc() void {}", "test.zig");
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnostics.items.len);
    try std.testing.expectEqual(rules.Rule.Z001, linter.diagnostics.items[0].rule);
}

test "Z001: allow camelCase function" {
    var linter: Linter = .init(std.testing.allocator, "fn myFunc() void {}", "test.zig");
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnostics.items.len);
}

test "Z001: allow snake_case function" {
    var linter: Linter = .init(std.testing.allocator, "fn my_func() void {}", "test.zig");
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnostics.items.len);
}

test "Z001: allow underscore prefix (private)" {
    var linter: Linter = .init(std.testing.allocator, "fn _privateFunc() void {}", "test.zig");
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnostics.items.len);
}

test "Z001: allow single lowercase letter" {
    var linter: Linter = .init(std.testing.allocator, "fn f() void {}", "test.zig");
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnostics.items.len);
}

// =============================================================================
// Z002: unused variable has a value
// =============================================================================

test "Z002: detect unused variable with value" {
    var linter: Linter = .init(std.testing.allocator, "fn foo() void { const _x = 1; }", "test.zig");
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnostics.items.len);
    try std.testing.expectEqual(rules.Rule.Z002, linter.diagnostics.items[0].rule);
}

test "Z002: allow plain discard _" {
    var linter: Linter = .init(std.testing.allocator, "fn foo() void { const _ = bar(); }", "test.zig");
    defer linter.deinit();
    linter.lint();
    for (linter.diagnostics.items) |d| {
        try std.testing.expect(d.rule != rules.Rule.Z002);
    }
}

test "Z002: allow double underscore __" {
    var linter: Linter = .init(std.testing.allocator, "fn foo() void { const __x = 1; }", "test.zig");
    defer linter.deinit();
    linter.lint();
    for (linter.diagnostics.items) |d| {
        try std.testing.expect(d.rule != rules.Rule.Z002);
    }
}

// =============================================================================
// Z003: parse error
// =============================================================================

test "Z003: detect parse error" {
    var linter: Linter = .init(std.testing.allocator, "const x = ", "test.zig");
    defer linter.deinit();
    linter.lint();
    try std.testing.expect(linter.diagnostics.items.len > 0);
    try std.testing.expectEqual(rules.Rule.Z003, linter.diagnostics.items[0].rule);
}

test "Z003: valid code no parse error" {
    var linter: Linter = .init(std.testing.allocator, "const x: u32 = 42;", "test.zig");
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnostics.items.len);
}

// =============================================================================
// Z004: prefer const foo: Foo = .{} over const foo = Foo{}
// =============================================================================

test "Z004: detect explicit struct init" {
    var linter: Linter = .init(std.testing.allocator, "const Foo = struct {}; fn bar() void { const x = Foo{}; _ = x; }", "test.zig");
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnostics.items.len);
    try std.testing.expectEqual(rules.Rule.Z004, linter.diagnostics.items[0].rule);
}

test "Z004: detect explicit struct init with fields" {
    var linter: Linter = .init(std.testing.allocator, "const Foo = struct { x: u32 }; fn bar() void { const f = Foo{ .x = 1 }; _ = f; }", "test.zig");
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnostics.items.len);
    try std.testing.expectEqual(rules.Rule.Z004, linter.diagnostics.items[0].rule);
}

test "Z004: allow anonymous struct init with type annotation" {
    var linter: Linter = .init(std.testing.allocator, "const Foo = struct {}; fn bar() void { const x: Foo = .{}; _ = x; }", "test.zig");
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnostics.items.len);
}

test "Z004: allow anonymous struct init with fields" {
    var linter: Linter = .init(std.testing.allocator, "const Foo = struct { x: u32 }; fn bar() void { const f: Foo = .{ .x = 1 }; _ = f; }", "test.zig");
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnostics.items.len);
}

// =============================================================================
// Z005: type functions should be PascalCase
// =============================================================================

test "Z005: detect lowercase type function" {
    var linter: Linter = .init(std.testing.allocator, "fn myType() type { return struct {}; }", "test.zig");
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnostics.items.len);
    try std.testing.expectEqual(rules.Rule.Z005, linter.diagnostics.items[0].rule);
}

test "Z005: detect snake_case type function" {
    var linter: Linter = .init(std.testing.allocator, "fn my_type() type { return struct {}; }", "test.zig");
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnostics.items.len);
    try std.testing.expectEqual(rules.Rule.Z005, linter.diagnostics.items[0].rule);
}

test "Z005: allow PascalCase type function" {
    var linter: Linter = .init(std.testing.allocator, "fn MyType() type { return struct {}; }", "test.zig");
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnostics.items.len);
}

test "Z005: allow PascalCase generic type function" {
    var linter: Linter = .init(std.testing.allocator, "fn ArrayList(comptime T: type) type { return struct {}; }", "test.zig");
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnostics.items.len);
}

// =============================================================================
// Z006: variables should be snake_case
// =============================================================================

test "Z006: detect camelCase variable" {
    var linter: Linter = .init(std.testing.allocator, "fn foo() void { const myVar = 1; _ = myVar; }", "test.zig");
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnostics.items.len);
    try std.testing.expectEqual(rules.Rule.Z006, linter.diagnostics.items[0].rule);
}

test "Z006: detect PascalCase variable (not type)" {
    var linter: Linter = .init(std.testing.allocator, "fn foo() void { const MyVar = 1; _ = MyVar; }", "test.zig");
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnostics.items.len);
    try std.testing.expectEqual(rules.Rule.Z006, linter.diagnostics.items[0].rule);
}

test "Z006: allow snake_case variable" {
    var linter: Linter = .init(std.testing.allocator, "fn foo() void { const my_var = 1; _ = my_var; }", "test.zig");
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnostics.items.len);
}

test "Z006: allow single lowercase letter" {
    var linter: Linter = .init(std.testing.allocator, "fn foo() void { const x = 1; _ = x; }", "test.zig");
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnostics.items.len);
}

test "Z006: allow underscore prefix" {
    var linter: Linter = .init(std.testing.allocator, "fn foo() void { const _unused: u32 = undefined; _ = _unused; }", "test.zig");
    defer linter.deinit();
    linter.lint();
    for (linter.diagnostics.items) |d| {
        try std.testing.expect(d.rule != rules.Rule.Z006);
    }
}

// =============================================================================
// Z006: type alias exemptions
// =============================================================================

test "Z006: allow type alias with @This()" {
    var linter: Linter = .init(std.testing.allocator, "const MyType = @This();", "test.zig");
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnostics.items.len);
}

test "Z006: allow type alias with @import()" {
    var linter: Linter = .init(std.testing.allocator, "const Foo = @import(\"foo.zig\");", "test.zig");
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnostics.items.len);
}

test "Z006: allow type alias with @Type()" {
    var linter: Linter = .init(std.testing.allocator, "const MyType = @Type(.{ .int = .{ .signedness = .unsigned, .bits = 8 } });", "test.zig");
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnostics.items.len);
}

test "Z006: allow type alias with struct" {
    var linter: Linter = .init(std.testing.allocator, "const MyStruct = struct { x: u32 };", "test.zig");
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnostics.items.len);
}

test "Z006: allow type alias with enum" {
    var linter: Linter = .init(std.testing.allocator, "const MyEnum = enum { a, b, c };", "test.zig");
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnostics.items.len);
}

test "Z006: allow type alias with union" {
    var linter: Linter = .init(std.testing.allocator, "const MyUnion = union { x: u32, y: f32 };", "test.zig");
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnostics.items.len);
}

test "Z006: allow type alias with field access ending in PascalCase" {
    var linter: Linter = .init(std.testing.allocator, "const std = @import(\"std\"); const Ast = std.zig.Ast;", "test.zig");
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnostics.items.len);
}

test "Z006: detect field access ending in snake_case" {
    var linter: Linter = .init(std.testing.allocator, "const std = @import(\"std\"); const Thing = std.some_value;", "test.zig");
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnostics.items.len);
    try std.testing.expectEqual(rules.Rule.Z006, linter.diagnostics.items[0].rule);
}

test "Z006: allow PascalCase identifier assignment" {
    var linter: Linter = .init(std.testing.allocator, "const MyType = SomeType;", "test.zig");
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnostics.items.len);
}

test "Z006: detect snake_case identifier assignment" {
    var linter: Linter = .init(std.testing.allocator, "const MyThing = some_value;", "test.zig");
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnostics.items.len);
    try std.testing.expectEqual(rules.Rule.Z006, linter.diagnostics.items[0].rule);
}

// =============================================================================
// Inline ignore comments
// =============================================================================

test "inline ignore: single rule" {
    var linter: Linter = .init(std.testing.allocator, "fn foo() void { const myVar = 1; _ = myVar; } // ziglint-ignore: Z006", "test.zig");
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnostics.items.len);
}

test "inline ignore: multiple rules" {
    var linter: Linter = .init(std.testing.allocator, "fn MyFunc() void { const myVar = 1; _ = myVar; } // ziglint-ignore: Z001 Z006", "test.zig");
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnostics.items.len);
}

test "inline ignore: only ignores specified rule" {
    var linter: Linter = .init(std.testing.allocator, "fn MyFunc() void {} // ziglint-ignore: Z006", "test.zig");
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnostics.items.len);
    try std.testing.expectEqual(rules.Rule.Z001, linter.diagnostics.items[0].rule);
}

test "inline ignore: multiline - only affects that line" {
    var linter: Linter = .init(std.testing.allocator,
        \\fn MyFunc() void {} // ziglint-ignore: Z001
        \\fn AnotherBad() void {}
    , "test.zig");
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnostics.items.len);
    try std.testing.expectEqual(rules.Rule.Z001, linter.diagnostics.items[0].rule);
}

test "inline ignore: preceding line comment" {
    var linter: Linter = .init(std.testing.allocator,
        \\// ziglint-ignore: Z001
        \\fn MyFunc() void {}
    , "test.zig");
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnostics.items.len);
}

test "inline ignore: preceding line only affects next line" {
    var linter: Linter = .init(std.testing.allocator,
        \\// ziglint-ignore: Z001
        \\fn MyFunc() void {}
        \\fn AnotherBad() void {}
    , "test.zig");
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnostics.items.len);
    try std.testing.expectEqual(rules.Rule.Z001, linter.diagnostics.items[0].rule);
}

test "inline ignore: multiple preceding comment lines" {
    var linter: Linter = .init(std.testing.allocator,
        \\// ziglint-ignore: Z001
        \\// ziglint-ignore: Z006
        \\fn MyFunc() void { const myVar = 1; _ = myVar; }
    , "test.zig");
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnostics.items.len);
}

test "inline ignore: multiple preceding with other comments" {
    var linter: Linter = .init(std.testing.allocator,
        \\// ziglint-ignore: Z001
        \\// This function does something important
        \\// ziglint-ignore: Z006
        \\fn MyFunc() void { const myVar = 1; _ = myVar; }
    , "test.zig");
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnostics.items.len);
}
