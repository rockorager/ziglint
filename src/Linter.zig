//! Core linter that parses Zig source and runs lint rules.

const std = @import("std");
const Ast = std.zig.Ast;
const rules = @import("rules.zig");
const TypeResolver = @import("TypeResolver.zig");
const doc_comments = @import("doc_comments.zig");

const Linter = @This();

allocator: std.mem.Allocator,
source: [:0]const u8,
path: []const u8,
tree: Ast,
diagnostics: std.ArrayListUnmanaged(Diagnostic),
seen_imports: std.StringHashMapUnmanaged(Ast.TokenIndex),
type_resolver: ?*TypeResolver = null,
module_path: ?[]const u8 = null,
allocated_contexts: std.ArrayListUnmanaged([]const u8) = .empty,
public_types: std.StringHashMapUnmanaged(void) = .empty,
imported_types: std.StringHashMapUnmanaged(void) = .empty,
import_bindings: std.StringHashMapUnmanaged(ImportInfo) = .empty,
used_identifiers: std.StringHashMapUnmanaged(void) = .empty,

const ImportInfo = struct {
    name_token: Ast.TokenIndex,
    is_pub: bool,
    is_discard: bool,
};

pub const Diagnostic = struct {
    path: []const u8,
    line: u32,
    column: u32,
    rule: rules.Rule,
    context: []const u8 = "",

    // ANSI escape codes
    const dim = "\x1b[2m";
    const cyan = "\x1b[36m";
    const yellow = "\x1b[33m";
    const reset = "\x1b[0m";

    pub fn write(self: Diagnostic, writer: *std.Io.Writer, use_color: bool, display_path: []const u8) !void {
        if (use_color) {
            try writer.print("{s}{s}{s}{s}:{s} {s}{s}{s}:{s}{s}{}{s}{s}:{s} ", .{
                yellow,
                self.rule.code(),
                reset,
                dim,
                reset,
                dim,
                display_path,
                reset,
                dim,
                cyan,
                self.line,
                reset,
                dim,
                reset,
            });
        } else {
            try writer.print("{s}: {s}:{}: ", .{
                self.rule.code(),
                display_path,
                self.line,
            });
        }
        try self.rule.writeMessage(writer, self.context, use_color);
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
        .seen_imports = .empty,
    };
}

pub fn initWithSemantics(
    allocator: std.mem.Allocator,
    source: [:0]const u8,
    path: []const u8,
    type_resolver: *TypeResolver,
    module_path: []const u8,
) Linter {
    return .{
        .allocator = allocator,
        .source = source,
        .path = path,
        .tree = Ast.parse(allocator, source, .zig) catch unreachable,
        .diagnostics = .empty,
        .seen_imports = .empty,
        .type_resolver = type_resolver,
        .module_path = module_path,
    };
}

pub fn deinit(self: *Linter) void {
    for (self.allocated_contexts.items) |ctx| {
        self.allocator.free(ctx);
    }
    self.allocated_contexts.deinit(self.allocator);
    self.tree.deinit(self.allocator);
    self.diagnostics.deinit(self.allocator);
    self.seen_imports.deinit(self.allocator);
    self.public_types.deinit(self.allocator);
    self.imported_types.deinit(self.allocator);
    self.import_bindings.deinit(self.allocator);
    self.used_identifiers.deinit(self.allocator);
}

pub fn lint(self: *Linter) void {
    self.checkParseErrors();
    if (self.tree.errors.len > 0) return;

    self.checkCommentDividers();
    self.checkFileAsStruct();
    self.buildPublicTypesMap();
    self.collectAllIdentifiers();

    for (self.tree.rootDecls()) |node| {
        self.visitNode(node);
    }

    self.checkUnusedImports();
}

fn collectAllIdentifiers(self: *Linter) void {
    for (0..self.tree.nodes.len) |i| {
        const node: Ast.Node.Index = @enumFromInt(i);
        const tag = self.tree.nodeTag(node);
        switch (tag) {
            .identifier => {
                const name = self.tree.tokenSlice(self.tree.nodeMainToken(node));
                self.used_identifiers.put(self.allocator, name, {}) catch {};
            },
            .field_access => {
                // Walk field_access chain to find root identifier
                var current = node;
                while (self.tree.nodeTag(current) == .field_access) {
                    const data = self.tree.nodeData(current).node_and_token;
                    current = data[0];
                }
                if (self.tree.nodeTag(current) == .identifier) {
                    const name = self.tree.tokenSlice(self.tree.nodeMainToken(current));
                    self.used_identifiers.put(self.allocator, name, {}) catch {};
                }
            },
            else => {},
        }
    }
}

fn checkParseErrors(self: *Linter) void {
    for (self.tree.errors) |err| {
        const loc = self.tree.tokenLocation(0, err.token);
        self.report(loc, .Z003, "");
    }
}

fn checkUnusedImports(self: *Linter) void {
    var it = self.import_bindings.iterator();
    while (it.next()) |entry| {
        const name = entry.key_ptr.*;
        const info = entry.value_ptr.*;

        // Skip pub re-exports - they're intentionally exposed
        if (info.is_pub) continue;

        // Discarded imports `_ = @import(...)` are always unused
        if (info.is_discard) {
            const loc = self.tree.tokenLocation(0, info.name_token);
            self.report(loc, .Z013, name);
            continue;
        }

        // Check if the bound name is used elsewhere
        if (!self.used_identifiers.contains(name)) {
            const loc = self.tree.tokenLocation(0, info.name_token);
            self.report(loc, .Z013, name);
        }
    }
}

fn checkFileAsStruct(self: *Linter) void {
    // Check if file has top-level fields (container fields at root level)
    var has_top_level_fields = false;
    for (self.tree.rootDecls()) |node| {
        const tag = self.tree.nodeTag(node);
        if (tag == .container_field_init or tag == .container_field) {
            has_top_level_fields = true;
            break;
        }
    }

    if (!has_top_level_fields) return;

    // File has top-level fields, check if filename is PascalCase
    const basename = std.fs.path.basename(self.path);
    const name = if (std.mem.endsWith(u8, basename, ".zig"))
        basename[0 .. basename.len - 4]
    else
        basename;

    if (!isPascalCase(name)) {
        self.report(.{ .line = 0, .column = 0, .line_start = 0, .line_end = 0 }, .Z009, basename);
    }
}

fn checkCommentDividers(self: *Linter) void {
    var line_num: usize = 0;
    var line_start: usize = 0;

    for (self.source, 0..) |c, i| {
        if (c == '\n') {
            const line = self.source[line_start..i];
            if (isDividerComment(line)) {
                self.report(.{ .line = line_num, .column = 0, .line_start = line_start, .line_end = i }, .Z008, "");
            }
            line_num += 1;
            line_start = i + 1;
        }
    }

    // Check last line if no trailing newline
    if (line_start < self.source.len) {
        const line = self.source[line_start..];
        if (isDividerComment(line)) {
            self.report(.{ .line = line_num, .column = 0, .line_start = line_start, .line_end = self.source.len }, .Z008, "");
        }
    }
}

fn isDividerComment(line: []const u8) bool {
    const trimmed = std.mem.trimLeft(u8, line, " \t");
    if (!std.mem.startsWith(u8, trimmed, "//")) return false;

    const after_slashes = std.mem.trimLeft(u8, trimmed[2..], " ");
    if (after_slashes.len < 3) return false;

    // Check if mostly one repeated character
    const first = after_slashes[0];
    if (first != '=' and first != '-' and first != '*' and first != '#') return false;

    var count: usize = 0;
    for (after_slashes) |ch| {
        if (ch == first) count += 1;
    }

    return count * 100 / after_slashes.len >= 80;
}

fn buildPublicTypesMap(self: *Linter) void {
    for (self.tree.rootDecls()) |node| {
        const tag = self.tree.nodeTag(node);
        switch (tag) {
            .simple_var_decl, .aligned_var_decl, .local_var_decl, .global_var_decl => {
                const var_decl = self.tree.fullVarDecl(node) orelse continue;
                const name_token = var_decl.ast.mut_token + 1;
                const name = self.tree.tokenSlice(name_token);

                // Track imported types (field access ending in PascalCase, e.g., std.mem.Allocator)
                if (self.isImportedType(var_decl)) {
                    self.imported_types.put(self.allocator, name, {}) catch {};
                    continue;
                }

                if (!self.isPublicDecl(node)) continue;
                if (!self.isTypeDecl(var_decl)) continue;

                self.public_types.put(self.allocator, name, {}) catch {};
            },
            else => {},
        }
    }
}

fn isImportedType(self: *Linter, var_decl: Ast.full.VarDecl) bool {
    const init_node = var_decl.ast.init_node.unwrap() orelse return false;

    // Use type resolver if available
    if (self.type_resolver) |resolver| {
        if (self.module_path) |mod_path| {
            const type_info = resolver.typeOf(mod_path, init_node);
            return switch (type_info) {
                .type_type, .std_type, .user_type => true,
                else => false,
            };
        }
    }

    // Fallback: check if it's a field access ending in PascalCase
    const tag = self.tree.nodeTag(init_node);
    return switch (tag) {
        .field_access => blk: {
            const data = self.tree.nodeData(init_node).node_and_token;
            const field_name = self.tree.tokenSlice(data[1]);
            break :blk isPascalCase(field_name);
        },
        else => false,
    };
}

fn isPublicDecl(self: *Linter, node: Ast.Node.Index) bool {
    const main_token = self.tree.nodeMainToken(node);
    if (main_token == 0) return false;
    const prev_token = main_token - 1;
    const prev_slice = self.tree.tokenSlice(prev_token);
    return std.mem.eql(u8, prev_slice, "pub");
}

fn isTypeDecl(self: *Linter, var_decl: Ast.full.VarDecl) bool {
    const init_node = var_decl.ast.init_node.unwrap() orelse return false;
    return self.isTypeExpression(init_node);
}

fn isTypeExpression(self: *Linter, node: Ast.Node.Index) bool {
    const tag = self.tree.nodeTag(node);
    return switch (tag) {
        // Container types (struct, enum, union)
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
        // Pointer types (e.g., *anyopaque, *T)
        .ptr_type_aligned,
        .ptr_type_sentinel,
        .ptr_type,
        .ptr_type_bit_range,
        => true,
        // Optional types (e.g., ?T)
        .optional_type => true,
        // Array types (e.g., [N]T)
        .array_type,
        .array_type_sentinel,
        => true,
        // Error union types (e.g., E!T)
        .error_union => true,
        // Error set declarations (e.g., error{A, B})
        .error_set_decl => true,
        // Function types
        .fn_proto,
        .fn_proto_multi,
        .fn_proto_one,
        .fn_proto_simple,
        => true,
        // Builtin type constructors
        .builtin_call_two, .builtin_call_two_comma, .builtin_call, .builtin_call_comma => blk: {
            const token = self.tree.tokenSlice(self.tree.nodeMainToken(node));
            break :blk std.mem.eql(u8, token, "@Type");
        },
        // Identifier referencing another type (type alias)
        .identifier => blk: {
            const name = self.tree.tokenSlice(self.tree.nodeMainToken(node));
            break :blk isPascalCase(name) or isBuiltinType(name);
        },
        // Labeled blocks (comptime type construction, e.g., `key: { break :key @Type(...); }`)
        .block_two, .block_two_semicolon, .block, .block_semicolon => true,
        // Switch expressions (comptime type selection, e.g., `switch (os) { .linux => T1, else => T2 }`)
        .@"switch", .switch_comma => true,
        // If expressions (comptime type selection)
        .@"if", .if_simple => true,
        // Generic type instantiation (e.g., ArrayList(T), HashMap(K, V))
        .call_one, .call_one_comma, .call, .call_comma => true,
        // Field access (e.g., std.AutoHashMapUnmanaged)
        .field_access => blk: {
            const data = self.tree.nodeData(node).node_and_token;
            const field_name = self.tree.tokenSlice(data[1]);
            break :blk isPascalCase(field_name);
        },
        else => false,
    };
}

fn isPrivateTypeRef(self: *Linter, name: []const u8) bool {
    if (!isPascalCase(name)) return false;
    if (isBuiltinType(name)) return false;
    if (self.public_types.contains(name)) return false;
    if (self.imported_types.contains(name)) return false;
    // Don't flag Self type (type matching filename for file-as-struct pattern)
    if (self.isSelfType(name)) return false;
    return true;
}

fn isSelfType(self: *Linter, name: []const u8) bool {
    const basename = std.fs.path.basename(self.path);
    const stem = if (std.mem.endsWith(u8, basename, ".zig"))
        basename[0 .. basename.len - 4]
    else
        basename;
    return std.mem.eql(u8, name, stem);
}

fn isBuiltinType(name: []const u8) bool {
    const builtins = [_][]const u8{
        "u8",           "u16",            "u32",  "u64",      "u128",    "usize",
        "i8",           "i16",            "i32",  "i64",      "i128",    "isize",
        "f16",          "f32",            "f64",  "f80",      "f128",    "bool",
        "void",         "noreturn",       "type", "anyerror", "anytype", "anyframe",
        "comptime_int", "comptime_float",
    };
    for (builtins) |b| {
        if (std.mem.eql(u8, name, b)) return true;
    }
    return false;
}

fn checkExposedPrivateType(self: *Linter, node: Ast.Node.Index) void {
    var buf: [1]Ast.Node.Index = undefined;
    const fn_proto = self.tree.fullFnProto(&buf, node) orelse return;

    if (!self.isPublicDecl(node)) return;

    // Collect generic type parameter names
    var generic_params: [16][]const u8 = undefined;
    var generic_count: usize = 0;
    var it = fn_proto.iterate(&self.tree);
    while (it.next()) |param| {
        const type_node = param.type_expr orelse continue;
        if (self.tree.nodeTag(type_node) == .identifier) {
            const type_name = self.tree.tokenSlice(self.tree.nodeMainToken(type_node));
            if (std.mem.eql(u8, type_name, "type")) {
                if (param.name_token) |name_tok| {
                    if (generic_count < 16) {
                        generic_params[generic_count] = self.tree.tokenSlice(name_tok);
                        generic_count += 1;
                    }
                }
            }
        }
    }

    // Check return type
    if (fn_proto.ast.return_type.unwrap()) |ret_node| {
        self.checkTypeNodeForPrivateWithGenerics(ret_node, fn_proto, generic_params[0..generic_count]);
    }

    // Check parameter types
    var it2 = fn_proto.iterate(&self.tree);
    while (it2.next()) |param| {
        const type_node = param.type_expr orelse continue;
        // Skip generic parameters (comptime T: type)
        if (self.tree.nodeTag(type_node) == .identifier) {
            const type_name = self.tree.tokenSlice(self.tree.nodeMainToken(type_node));
            if (std.mem.eql(u8, type_name, "type")) continue;
        }
        self.checkTypeNodeForPrivateWithGenerics(type_node, fn_proto, generic_params[0..generic_count]);
    }
}

fn checkTypeNodeForPrivateWithGenerics(
    self: *Linter,
    type_node: Ast.Node.Index,
    fn_proto: Ast.full.FnProto,
    generic_params: []const []const u8,
) void {
    self.checkTypeNodeForPrivateImpl(type_node, fn_proto, generic_params, false);
}

fn checkTypeNodeForPrivateImpl(
    self: *Linter,
    type_node: Ast.Node.Index,
    fn_proto: Ast.full.FnProto,
    generic_params: []const []const u8,
    is_error_position: bool,
) void {
    const tag = self.tree.nodeTag(type_node);

    switch (tag) {
        .identifier => {
            const type_name = self.tree.tokenSlice(self.tree.nodeMainToken(type_node));
            // Skip generic type parameters
            for (generic_params) |gp| {
                if (std.mem.eql(u8, type_name, gp)) return;
            }
            if (self.isPrivateTypeRef(type_name)) {
                self.reportPrivateType(fn_proto, type_name, is_error_position);
            }
        },
        .optional_type => {
            const child = self.tree.nodeData(type_node).node;
            self.checkTypeNodeForPrivateImpl(child, fn_proto, generic_params, is_error_position);
        },
        .error_union => {
            const data = self.tree.nodeData(type_node).node_and_node;
            self.checkTypeNodeForPrivateImpl(data[0], fn_proto, generic_params, true);
            self.checkTypeNodeForPrivateImpl(data[1], fn_proto, generic_params, false);
        },
        else => {},
    }
}

fn reportPrivateType(self: *Linter, fn_proto: Ast.full.FnProto, type_name: []const u8, is_error: bool) void {
    const name_token = fn_proto.name_token orelse return;
    const loc = self.tree.tokenLocation(0, name_token);
    const rule: rules.Rule = if (is_error) .Z015 else .Z012;
    self.report(loc, rule, type_name);
}

fn visitNode(self: *Linter, node: Ast.Node.Index) void {
    const tag = self.tree.nodeTag(node);

    switch (tag) {
        .fn_decl => self.checkFnDecl(node),
        .simple_var_decl, .aligned_var_decl, .local_var_decl, .global_var_decl => self.checkVarDecl(node),
        .@"return" => self.checkReturn(node),
        .call_one, .call_one_comma, .call, .call_comma => {
            self.checkCallArgs(node);
            self.checkDeprecatedCall(node);
            self.checkCompoundAssert(node);
        },
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

    self.checkExposedPrivateType(node);
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

    // Check that error sets are PascalCase
    if (var_decl.ast.init_node.unwrap()) |init_node| {
        if (self.tree.nodeTag(init_node) == .error_set_decl and !isPascalCase(name)) {
            const loc = self.tree.tokenLocation(0, name_token);
            self.report(loc, .Z014, name);
        }
    }

    if (var_decl.ast.type_node == .none) {
        if (var_decl.ast.init_node.unwrap()) |init_node| {
            if (isExplicitStructInit(self.tree.nodeTag(init_node))) {
                const loc = self.tree.tokenLocation(0, var_decl.ast.mut_token);
                self.report(loc, .Z004, name);
            }
        }
    }

    self.checkDupeImport(var_decl, name_token);
    self.trackImportBinding(node, var_decl, name_token);
}

fn trackImportBinding(self: *Linter, node: Ast.Node.Index, var_decl: Ast.full.VarDecl, name_token: Ast.TokenIndex) void {
    const init_node = var_decl.ast.init_node.unwrap() orelse return;

    // Check if this is a @import call
    const main_token = self.tree.nodeMainToken(init_node);
    const builtin_name = self.tree.tokenSlice(main_token);
    if (!std.mem.eql(u8, builtin_name, "@import")) return;

    const name = self.tree.tokenSlice(name_token);
    const is_discard = std.mem.eql(u8, name, "_");
    const is_pub = self.isPublicDecl(node);

    self.import_bindings.put(self.allocator, name, .{
        .name_token = name_token,
        .is_pub = is_pub,
        .is_discard = is_discard,
    }) catch {};
}

fn checkDupeImport(self: *Linter, var_decl: Ast.full.VarDecl, name_token: Ast.TokenIndex) void {
    const init_node = var_decl.ast.init_node.unwrap() orelse return;

    // Check if this is a @import call
    const main_token = self.tree.nodeMainToken(init_node);
    const builtin_name = self.tree.tokenSlice(main_token);
    if (!std.mem.eql(u8, builtin_name, "@import")) return;

    // Get the import argument
    var buf: [2]Ast.Node.Index = undefined;
    const params = self.tree.builtinCallParams(&buf, init_node) orelse return;
    if (params.len == 0) return;

    const arg_token = self.tree.nodeMainToken(params[0]);
    const import_path = self.tree.tokenSlice(arg_token);

    // Check for duplicate
    if (self.seen_imports.get(import_path)) |_| {
        const loc = self.tree.tokenLocation(0, name_token);
        self.report(loc, .Z007, import_path);
    } else {
        self.seen_imports.put(self.allocator, import_path, name_token) catch {};
    }
}

fn checkReturn(self: *Linter, node: Ast.Node.Index) void {
    const return_expr = self.tree.nodeData(node).opt_node.unwrap() orelse return;
    self.checkRedundantType(return_expr, true);
    self.checkReturnTry(node, return_expr);
}

fn checkReturnTry(self: *Linter, return_node: Ast.Node.Index, return_expr: Ast.Node.Index) void {
    // Check if the return expression is a try
    if (self.tree.nodeTag(return_expr) != .@"try") return;

    // Get the inner expression being tried
    const try_expr = self.tree.nodeData(return_expr).node;
    const expr_source = self.getNodeSource(try_expr);
    const truncated = truncateExpr(expr_source);

    const loc = self.tree.tokenLocation(0, self.tree.nodeMainToken(return_node));
    self.report(loc, .Z017, truncated);
}

fn checkCallArgs(self: *Linter, node: Ast.Node.Index) void {
    var buf: [1]Ast.Node.Index = undefined;
    const call = self.tree.fullCall(&buf, node) orelse return;
    for (call.ast.params) |arg| {
        // Don't check field_access in call args - can't distinguish type params from enum values
        self.checkRedundantType(arg, false);
    }
}

fn checkDeprecatedCall(self: *Linter, node: Ast.Node.Index) void {
    const resolver = self.type_resolver orelse return;
    const mod_path = self.module_path orelse return;

    var buf: [1]Ast.Node.Index = undefined;
    const call = self.tree.fullCall(&buf, node) orelse return;

    const fn_expr = call.ast.fn_expr;
    if (self.tree.nodeTag(fn_expr) != .field_access) return;

    const data = self.tree.nodeData(fn_expr).node_and_token;
    const receiver_node = data[0];
    const method_token = data[1];
    const method_name = self.tree.tokenSlice(method_token);

    const receiver_type = resolver.typeOf(mod_path, receiver_node);

    const method_def = resolver.findMethodDef(receiver_type, method_name) orelse return;

    const mod = resolver.graph.getModule(method_def.module_path) orelse return;
    const doc = doc_comments.getDocComment(self.allocator, &mod.tree, method_def.node) orelse return;
    defer self.allocator.free(doc);

    if (containsDeprecated(doc)) {
        const loc = self.tree.tokenLocation(0, method_token);
        // Build message with doc comment
        const msg = std.fmt.allocPrint(self.allocator, "'{s}' is deprecated: {s}", .{ method_name, doc }) catch return;
        self.allocated_contexts.append(self.allocator, msg) catch {
            self.allocator.free(msg);
            return;
        };
        self.report(loc, .Z011, msg);
    }
}

fn containsDeprecated(text: []const u8) bool {
    var i: usize = 0;
    while (i + 10 <= text.len) : (i += 1) {
        const slice = text[i .. i + 10];
        if (std.ascii.eqlIgnoreCase(slice, "deprecated")) return true;
    }
    return false;
}

fn checkCompoundAssert(self: *Linter, node: Ast.Node.Index) void {
    var buf: [1]Ast.Node.Index = undefined;
    const call = self.tree.fullCall(&buf, node) orelse return;

    // Check if this is a call to "assert"
    const fn_expr = call.ast.fn_expr;
    const is_assert = switch (self.tree.nodeTag(fn_expr)) {
        .identifier => std.mem.eql(u8, self.tree.tokenSlice(self.tree.nodeMainToken(fn_expr)), "assert"),
        .field_access => blk: {
            const data = self.tree.nodeData(fn_expr).node_and_token;
            break :blk std.mem.eql(u8, self.tree.tokenSlice(data[1]), "assert");
        },
        else => false,
    };
    if (!is_assert) return;

    // Check if argument is a compound bool_and or bool_or
    if (call.ast.params.len == 0) return;
    const arg = call.ast.params[0];
    const arg_tag = self.tree.nodeTag(arg);

    // Only flag `and` - `assert(a or b)` is not equivalent to `assert(a); assert(b);`
    if (arg_tag != .bool_and) return;

    const loc = self.tree.tokenLocation(0, self.tree.nodeMainToken(node));
    self.report(loc, .Z016, "and");
}

fn checkRedundantType(self: *Linter, node: Ast.Node.Index, check_field_access: bool) void {
    const tag = self.tree.nodeTag(node);

    if (isExplicitStructInit(tag)) {
        var buf: [2]Ast.Node.Index = undefined;
        const struct_init = self.tree.fullStructInit(&buf, node) orelse return;
        const type_node = struct_init.ast.type_expr.unwrap() orelse return;
        const type_token = self.tree.nodeMainToken(type_node);
        const loc = self.tree.tokenLocation(0, type_token);
        // Get the fields part (everything after the type name)
        const full_expr = self.getNodeSource(node);
        const type_name = self.tree.tokenSlice(type_token);
        // Find where the type name ends and extract the { ... } part
        const brace_start = std.mem.indexOf(u8, full_expr, "{") orelse return;
        const fields_part = truncateExpr(full_expr[brace_start..]);
        const full_truncated = truncateExpr(full_expr);
        const msg = std.fmt.allocPrint(self.allocator, ".{s}\x00{s}", .{ fields_part, full_truncated }) catch return;
        self.allocated_contexts.append(self.allocator, msg) catch {
            self.allocator.free(msg);
            return;
        };
        _ = type_name;
        self.report(loc, .Z010, msg);
    } else if (check_field_access and tag == .field_access) {
        // Only flag if the LHS is a PascalCase identifier (likely a type/enum)
        const data = self.tree.nodeData(node).node_and_token;
        const lhs = data[0];
        if (self.tree.nodeTag(lhs) != .identifier) return;
        const lhs_name = self.tree.tokenSlice(self.tree.nodeMainToken(lhs));
        if (!isPascalCase(lhs_name)) return;

        // Skip error sets - explicit Error.X is often preferred for clarity
        if (self.type_resolver) |resolver| {
            if (self.module_path) |mod_path| {
                const lhs_type = resolver.typeOf(mod_path, lhs);
                if (lhs_type == .error_set) return;
            }
        }

        const field_token = data[1];
        const field_name = self.tree.tokenSlice(field_token);
        const loc = self.tree.tokenLocation(0, self.tree.nodeMainToken(lhs));
        // Full expression is "Type.field"
        const full_expr = truncateExpr(self.getNodeSource(node));
        const msg = std.fmt.allocPrint(self.allocator, ".{s}\x00{s}", .{ field_name, full_expr }) catch return;
        self.allocated_contexts.append(self.allocator, msg) catch {
            self.allocator.free(msg);
            return;
        };
        self.report(loc, .Z010, msg);
    }
}

fn getNodeSource(self: *Linter, node: Ast.Node.Index) []const u8 {
    const token_starts = self.tree.tokens.items(.start);
    const first_token = self.tree.firstToken(node);
    const last_token = self.tree.lastToken(node);
    const start = token_starts[first_token];
    const end = token_starts[last_token] + self.tree.tokenSlice(last_token).len;
    return self.source[start..end];
}

fn truncateExpr(expr: []const u8) []const u8 {
    const max_len = 32;
    if (expr.len <= max_len) return expr;
    // Find a good break point (after opening brace if present)
    if (std.mem.indexOf(u8, expr[0..@min(max_len, expr.len)], "{")) |brace| {
        return expr[0 .. brace + 1];
    }
    return expr[0..max_len];
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
        .call_one, .call_one_comma => blk: {
            // Check if calling a PascalCase function (type constructor)
            const callee = self.tree.nodeData(init_node).node_and_opt_node[0];
            const callee_tag = self.tree.nodeTag(callee);
            if (callee_tag == .identifier) {
                const fn_name = self.tree.tokenSlice(self.tree.nodeMainToken(callee));
                break :blk isPascalCase(fn_name);
            } else if (callee_tag == .field_access) {
                const data = self.tree.nodeData(callee).node_and_token;
                const field_name = self.tree.tokenSlice(data[1]);
                break :blk isPascalCase(field_name);
            }
            break :blk false;
        },
        .call, .call_comma => blk: {
            // Check if calling a PascalCase function (type constructor)
            const callee = self.tree.nodeData(init_node).node_and_extra[0];
            const callee_tag = self.tree.nodeTag(callee);
            if (callee_tag == .identifier) {
                const fn_name = self.tree.tokenSlice(self.tree.nodeMainToken(callee));
                break :blk isPascalCase(fn_name);
            } else if (callee_tag == .field_access) {
                const data = self.tree.nodeData(callee).node_and_token;
                const field_name = self.tree.tokenSlice(data[1]);
                break :blk isPascalCase(field_name);
            }
            break :blk false;
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
        .error_set_decl,
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
    for (linter.diagnostics.items) |d| {
        try std.testing.expect(d.rule != rules.Rule.Z006);
    }
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

test "Z006: allow error set type" {
    var linter: Linter = .init(std.testing.allocator, "const Oom = error{OutOfMemory};", "test.zig");
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnostics.items.len);
}

test "Z006: allow type function call" {
    var linter: Linter = .init(std.testing.allocator, "fn GenericType(comptime T: type) type { return struct {}; } const MyType = GenericType(u32);", "test.zig");
    defer linter.deinit();
    linter.lint();
    for (linter.diagnostics.items) |d| {
        try std.testing.expect(d.rule != rules.Rule.Z006);
    }
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

test "Z007: duplicate import" {
    var linter: Linter = .init(std.testing.allocator,
        \\const std = @import("std");
        \\const std2 = @import("std");
        \\const x = std;
        \\const y = std2;
    , "test.zig");
    defer linter.deinit();
    linter.lint();
    var z007_count: usize = 0;
    for (linter.diagnostics.items) |d| {
        if (d.rule == rules.Rule.Z007) z007_count += 1;
    }
    try std.testing.expectEqual(1, z007_count);
}

test "Z007: different imports allowed" {
    var linter: Linter = .init(std.testing.allocator,
        \\const std = @import("std");
        \\const foo = @import("foo.zig");
        \\const x = std;
        \\const y = foo;
    , "test.zig");
    defer linter.deinit();
    linter.lint();
    for (linter.diagnostics.items) |d| {
        try std.testing.expect(d.rule != rules.Rule.Z007);
    }
}

test "Z007: multiple duplicates" {
    var linter: Linter = .init(std.testing.allocator,
        \\const std = @import("std");
        \\const std2 = @import("std");
        \\const std3 = @import("std");
        \\const x = std;
        \\const y = std2;
        \\const z = std3;
    , "test.zig");
    defer linter.deinit();
    linter.lint();
    var z007_count: usize = 0;
    for (linter.diagnostics.items) |d| {
        if (d.rule == rules.Rule.Z007) z007_count += 1;
    }
    try std.testing.expectEqual(2, z007_count);
}

test "Z008: detect comment divider with equals" {
    var linter: Linter = .init(std.testing.allocator, "// ========================================", "test.zig");
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnostics.items.len);
    try std.testing.expectEqual(rules.Rule.Z008, linter.diagnostics.items[0].rule);
}

test "Z008: detect comment divider with dashes" {
    var linter: Linter = .init(std.testing.allocator, "// ----------------------------------------", "test.zig");
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnostics.items.len);
    try std.testing.expectEqual(rules.Rule.Z008, linter.diagnostics.items[0].rule);
}

test "Z008: detect short separators" {
    var linter: Linter = .init(std.testing.allocator, "// ----", "test.zig");
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnostics.items.len);
    try std.testing.expectEqual(rules.Rule.Z008, linter.diagnostics.items[0].rule);
}

test "Z008: allow normal comments" {
    var linter: Linter = .init(std.testing.allocator, "// This is a normal comment", "test.zig");
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnostics.items.len);
}

test "Z009: file with top-level fields needs PascalCase name" {
    var linter: Linter = .init(std.testing.allocator, "foo: u32 = 0,", "my_module.zig");
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnostics.items.len);
    try std.testing.expectEqual(rules.Rule.Z009, linter.diagnostics.items[0].rule);
}

test "Z009: file with top-level fields and PascalCase name is ok" {
    var linter: Linter = .init(std.testing.allocator, "foo: u32 = 0,", "MyModule.zig");
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnostics.items.len);
}

test "Z009: file without top-level fields can be lowercase" {
    var linter: Linter = .init(std.testing.allocator, "const x: u32 = 0;", "main.zig");
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnostics.items.len);
}

test "Z010: detect explicit struct in return" {
    var linter: Linter = .init(std.testing.allocator, "fn foo() Foo { return Foo{}; }", "test.zig");
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnostics.items.len);
    try std.testing.expectEqual(rules.Rule.Z010, linter.diagnostics.items[0].rule);
}

test "Z010: allow anonymous struct in return" {
    var linter: Linter = .init(std.testing.allocator, "fn foo() Foo { return .{}; }", "test.zig");
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnostics.items.len);
}

test "Z010: detect explicit struct in function arg" {
    var linter: Linter = .init(std.testing.allocator, "fn bar(x: Foo) void {} fn foo() void { bar(Foo{}); }", "test.zig");
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnostics.items.len);
    try std.testing.expectEqual(rules.Rule.Z010, linter.diagnostics.items[0].rule);
}

test "Z010: allow anonymous struct in function arg" {
    var linter: Linter = .init(std.testing.allocator, "fn bar(x: Foo) void {} fn foo() void { bar(.{}); }", "test.zig");
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnostics.items.len);
}

test "Z010: detect explicit enum in return" {
    var linter: Linter = .init(std.testing.allocator, "fn foo() Mode { return Mode.fast; }", "test.zig");
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnostics.items.len);
    try std.testing.expectEqual(rules.Rule.Z010, linter.diagnostics.items[0].rule);
}

test "Z010: allow anonymous enum in return" {
    var linter: Linter = .init(std.testing.allocator, "fn foo() Mode { return .fast; }", "test.zig");
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnostics.items.len);
}

test "Z010: allow field access on non-type (self.field)" {
    var linter: Linter = .init(std.testing.allocator, "fn foo(self: *Self) u32 { return self.value; }", "test.zig");
    defer linter.deinit();
    linter.lint();
    for (linter.diagnostics.items) |d| {
        try std.testing.expect(d.rule != rules.Rule.Z010);
    }
}

test "Z011: detect deprecated method call" {
    const ModuleGraph = @import("ModuleGraph.zig");
    const source =
        \\const MyType = struct {
        \\    value: u32 = 0,
        \\    /// Deprecated: use newMethod instead
        \\    pub fn oldMethod(self: *@This()) void {
        \\        _ = self;
        \\    }
        \\};
        \\const instance: MyType = .{};
        \\pub fn main() void {
        \\    instance.oldMethod();
        \\}
    ;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    try tmp_dir.dir.writeFile(.{ .sub_path = "test.zig", .data = source });
    const path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, "test.zig");
    defer std.testing.allocator.free(path);

    var graph = try ModuleGraph.init(std.testing.allocator, path, null);
    defer graph.deinit();

    var resolver: TypeResolver = .init(std.testing.allocator, &graph);
    defer resolver.deinit();

    var linter: Linter = .initWithSemantics(std.testing.allocator, source, path, &resolver, path);
    defer linter.deinit();

    linter.lint();

    var found_z011 = false;
    for (linter.diagnostics.items) |d| {
        if (d.rule == rules.Rule.Z011) {
            found_z011 = true;
            break;
        }
    }
    try std.testing.expect(found_z011);
}

test "Z011: no warning for non-deprecated method" {
    const ModuleGraph = @import("ModuleGraph.zig");
    const source =
        \\const MyType = struct {
        \\    value: u32,
        \\    /// Does something useful
        \\    pub fn goodMethod(self: *@This()) void {
        \\        _ = self;
        \\    }
        \\};
        \\pub fn main() void {
        \\    var x: MyType = .{ .value = 0 };
        \\    x.goodMethod();
        \\}
    ;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    try tmp_dir.dir.writeFile(.{ .sub_path = "test.zig", .data = source });
    const path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, "test.zig");
    defer std.testing.allocator.free(path);

    var graph = try ModuleGraph.init(std.testing.allocator, path, null);
    defer graph.deinit();

    var resolver: TypeResolver = .init(std.testing.allocator, &graph);
    defer resolver.deinit();

    var linter: Linter = .initWithSemantics(std.testing.allocator, source, path, &resolver, path);
    defer linter.deinit();

    linter.lint();

    for (linter.diagnostics.items) |d| {
        try std.testing.expect(d.rule != rules.Rule.Z011);
    }
}

test "Z011: without semantic context, no Z011 warnings" {
    const source =
        \\const MyType = struct {
        \\    /// Deprecated
        \\    pub fn oldMethod(self: *@This()) void { _ = self; }
        \\};
        \\pub fn main() void {
        \\    var x: MyType = .{};
        \\    x.oldMethod();
        \\}
    ;

    var linter: Linter = .init(std.testing.allocator, source, "test.zig");
    defer linter.deinit();
    linter.lint();

    for (linter.diagnostics.items) |d| {
        try std.testing.expect(d.rule != rules.Rule.Z011);
    }
}

test "containsDeprecated" {
    try std.testing.expect(containsDeprecated("Deprecated: use X instead"));
    try std.testing.expect(containsDeprecated("deprecated function"));
    try std.testing.expect(containsDeprecated("This is DEPRECATED"));
    try std.testing.expect(!containsDeprecated("This function is useful"));
    try std.testing.expect(!containsDeprecated("deprecat")); // too short
}

test "Z012: pub fn returning private type" {
    var linter: Linter = .init(std.testing.allocator,
        \\const Private = struct {};
        \\pub fn getPrivate() Private { return .{}; }
    , "test.zig");
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnostics.items.len);
    try std.testing.expectEqual(rules.Rule.Z012, linter.diagnostics.items[0].rule);
}

test "Z012: pub fn accepting private type parameter" {
    var linter: Linter = .init(std.testing.allocator,
        \\const Private = struct {};
        \\pub fn usePrivate(p: Private) void { _ = p; }
    , "test.zig");
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnostics.items.len);
    try std.testing.expectEqual(rules.Rule.Z012, linter.diagnostics.items[0].rule);
}

test "Z012: pub fn returning optional private type" {
    var linter: Linter = .init(std.testing.allocator,
        \\const Private = struct {};
        \\pub fn maybePrivate() ?Private { return null; }
    , "test.zig");
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnostics.items.len);
    try std.testing.expectEqual(rules.Rule.Z012, linter.diagnostics.items[0].rule);
}

test "Z012: pub fn returning error union with private type" {
    var linter: Linter = .init(std.testing.allocator,
        \\const Private = struct {};
        \\pub fn getPrivateOrError() !Private { return .{}; }
    , "test.zig");
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnostics.items.len);
    try std.testing.expectEqual(rules.Rule.Z012, linter.diagnostics.items[0].rule);
}

test "Z015: pub fn returning private error set" {
    var linter: Linter = .init(std.testing.allocator,
        \\const Oom = error{OutOfMemory};
        \\pub fn doThing() Oom!void {}
    , "test.zig");
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnostics.items.len);
    try std.testing.expectEqual(rules.Rule.Z015, linter.diagnostics.items[0].rule);
}

test "Z012: pub fn returning public type is ok" {
    var linter: Linter = .init(std.testing.allocator,
        \\pub const Public = struct {};
        \\pub fn getPublic() Public { return .{}; }
    , "test.zig");
    defer linter.deinit();
    linter.lint();
    for (linter.diagnostics.items) |d| {
        try std.testing.expect(d.rule != rules.Rule.Z012);
    }
}

test "Z012: pub fn returning builtin type is ok" {
    var linter: Linter = .init(std.testing.allocator,
        \\pub fn getValue() u32 { return 42; }
    , "test.zig");
    defer linter.deinit();
    linter.lint();
    for (linter.diagnostics.items) |d| {
        try std.testing.expect(d.rule != rules.Rule.Z012);
    }
}

test "Z012: non-pub fn returning private type is ok" {
    var linter: Linter = .init(std.testing.allocator,
        \\const Private = struct {};
        \\fn getPrivate() Private { return .{}; }
    , "test.zig");
    defer linter.deinit();
    linter.lint();
    for (linter.diagnostics.items) |d| {
        try std.testing.expect(d.rule != rules.Rule.Z012);
    }
}

test "Z012: generic parameter with comptime T: type is ok" {
    var linter: Linter = .init(std.testing.allocator,
        \\pub fn genericFn(comptime T: type) T { return undefined; }
    , "test.zig");
    defer linter.deinit();
    linter.lint();
    for (linter.diagnostics.items) |d| {
        try std.testing.expect(d.rule != rules.Rule.Z012);
    }
}

test "Z012: pub fn returning public pointer type alias is ok" {
    var linter: Linter = .init(std.testing.allocator,
        \\pub const Queue = *anyopaque;
        \\pub fn getMain() Queue { return undefined; }
    , "test.zig");
    defer linter.deinit();
    linter.lint();
    for (linter.diagnostics.items) |d| {
        try std.testing.expect(d.rule != rules.Rule.Z012);
    }
}

test "Z012: pub fn returning public comptime block type is ok" {
    var linter: Linter = .init(std.testing.allocator,
        \\pub const Key = key: { break :key u32; };
        \\pub fn getKey() Key { return 0; }
    , "test.zig");
    defer linter.deinit();
    linter.lint();
    for (linter.diagnostics.items) |d| {
        try std.testing.expect(d.rule != rules.Rule.Z012);
    }
}

test "Z012: pub fn returning public switch type alias is ok" {
    var linter: Linter = .init(std.testing.allocator,
        \\pub const MyType = switch (true) { true => u32, false => i32 };
        \\pub fn getValue() MyType { return 0; }
    , "test.zig");
    defer linter.deinit();
    linter.lint();
    for (linter.diagnostics.items) |d| {
        try std.testing.expect(d.rule != rules.Rule.Z012);
    }
}

test "Z012: pub fn returning public generic type instantiation is ok" {
    var linter: Linter = .init(std.testing.allocator,
        \\const std = @import("std");
        \\pub const MyList = std.ArrayList(u32);
        \\pub fn getList() MyList { return undefined; }
    , "test.zig");
    defer linter.deinit();
    linter.lint();
    for (linter.diagnostics.items) |d| {
        try std.testing.expect(d.rule != rules.Rule.Z012);
    }
}

test "Z012: pub fn returning public field access type alias is ok" {
    var linter: Linter = .init(std.testing.allocator,
        \\const std = @import("std");
        \\pub const Allocator = std.mem.Allocator;
        \\pub fn getAllocator() Allocator { return undefined; }
    , "test.zig");
    defer linter.deinit();
    linter.lint();
    for (linter.diagnostics.items) |d| {
        try std.testing.expect(d.rule != rules.Rule.Z012);
    }
}

test "Z012: pub fn returning public error set is ok" {
    var linter: Linter = .init(std.testing.allocator,
        \\pub const MyError = error{ OutOfMemory, InvalidInput };
        \\pub fn toInt(err: MyError) u32 { _ = err; return 0; }
    , "test.zig");
    defer linter.deinit();
    linter.lint();
    for (linter.diagnostics.items) |d| {
        try std.testing.expect(d.rule != rules.Rule.Z012);
    }
}

test "Z012: pub fn returning public if expression type is ok" {
    var linter: Linter = .init(std.testing.allocator,
        \\pub const MyType = if (true) u32 else i32;
        \\pub fn getValue() MyType { return 0; }
    , "test.zig");
    defer linter.deinit();
    linter.lint();
    for (linter.diagnostics.items) |d| {
        try std.testing.expect(d.rule != rules.Rule.Z012);
    }
}

test "Z013: detect unused import" {
    var linter: Linter = .init(std.testing.allocator,
        \\const foo = @import("foo.zig");
    , "test.zig");
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnostics.items.len);
    try std.testing.expectEqual(rules.Rule.Z013, linter.diagnostics.items[0].rule);
}

test "Z013: import used via field access is ok" {
    var linter: Linter = .init(std.testing.allocator,
        \\const std = @import("std");
        \\const mem = std.mem;
    , "test.zig");
    defer linter.deinit();
    linter.lint();
    for (linter.diagnostics.items) |d| {
        try std.testing.expect(d.rule != rules.Rule.Z013);
    }
}

test "Z013: discarded import at root should warn" {
    var linter: Linter = .init(std.testing.allocator,
        \\const _ = @import("foo.zig");
    , "test.zig");
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnostics.items.len);
    try std.testing.expectEqual(rules.Rule.Z013, linter.diagnostics.items[0].rule);
}

test "Z013: discarded import in test block is ok" {
    var linter: Linter = .init(std.testing.allocator,
        \\test {
        \\    _ = @import("foo.zig");
        \\}
    , "test.zig");
    defer linter.deinit();
    linter.lint();
    for (linter.diagnostics.items) |d| {
        try std.testing.expect(d.rule != rules.Rule.Z013);
    }
}

test "Z013: pub re-export is not unused" {
    var linter: Linter = .init(std.testing.allocator,
        \\pub const foo = @import("foo.zig");
    , "test.zig");
    defer linter.deinit();
    linter.lint();
    for (linter.diagnostics.items) |d| {
        try std.testing.expect(d.rule != rules.Rule.Z013);
    }
}

test "Z013: import used as identifier is ok" {
    var linter: Linter = .init(std.testing.allocator,
        \\const foo = @import("foo.zig");
        \\const bar = foo;
    , "test.zig");
    defer linter.deinit();
    linter.lint();
    for (linter.diagnostics.items) |d| {
        try std.testing.expect(d.rule != rules.Rule.Z013);
    }
}

test "Z014: detect snake_case error set" {
    var linter: Linter = .init(std.testing.allocator, "const my_error = error{OutOfMemory};", "test.zig");
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnostics.items.len);
    try std.testing.expectEqual(rules.Rule.Z014, linter.diagnostics.items[0].rule);
}

test "Z014: allow PascalCase error set" {
    var linter: Linter = .init(std.testing.allocator, "const Oom = error{OutOfMemory};", "test.zig");
    defer linter.deinit();
    linter.lint();
    for (linter.diagnostics.items) |d| {
        try std.testing.expect(d.rule != rules.Rule.Z014);
    }
}

test "Z016: detect compound assert with and" {
    var linter: Linter = .init(std.testing.allocator,
        \\const std = @import("std");
        \\fn foo() void {
        \\    std.debug.assert(a and b);
        \\}
    , "test.zig");
    defer linter.deinit();
    linter.lint();
    var found = false;
    for (linter.diagnostics.items) |d| {
        if (d.rule == rules.Rule.Z016) {
            found = true;
            try std.testing.expectEqualStrings("and", d.context);
        }
    }
    try std.testing.expect(found);
}

test "Z016: assert with or is ok (different semantics)" {
    var linter: Linter = .init(std.testing.allocator,
        \\const assert = @import("std").debug.assert;
        \\fn foo() void {
        \\    assert(x or y);
        \\}
    , "test.zig");
    defer linter.deinit();
    linter.lint();
    for (linter.diagnostics.items) |d| {
        try std.testing.expect(d.rule != rules.Rule.Z016);
    }
}

test "Z016: simple assert is ok" {
    var linter: Linter = .init(std.testing.allocator,
        \\const std = @import("std");
        \\fn foo() void {
        \\    std.debug.assert(a);
        \\}
    , "test.zig");
    defer linter.deinit();
    linter.lint();
    for (linter.diagnostics.items) |d| {
        try std.testing.expect(d.rule != rules.Rule.Z016);
    }
}
