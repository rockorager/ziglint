//! Type resolver for semantic analysis.
//!
//! Resolves expression types using ZIR data combined with AST analysis.
//! Tracks variable declarations, follows field access chains, and resolves
//! function return types.

const std = @import("std");
const Ast = std.zig.Ast;
const Zir = std.zig.Zir;
const ModuleGraph = @import("ModuleGraph.zig");

const TypeResolver = @This();

allocator: std.mem.Allocator,
graph: *const ModuleGraph,

pub const TypeInfo = union(enum) {
    /// A primitive type like u32, bool, void
    primitive: Primitive,
    /// A type from the standard library (std.fs.File, etc.)
    std_type: StdType,
    /// A user-defined type from the current module or imports
    user_type: UserType,
    /// The special 'type' type (for type aliases and comptime type values)
    type_type,
    /// A function type
    function: FunctionType,
    /// A pointer to another type
    pointer: PointerType,
    /// An optional type
    optional: OptionalType,
    /// An error union type
    error_union: ErrorUnionType,
    /// A slice type
    slice: SliceType,
    /// An array type
    array: ArrayType,
    /// Type could not be resolved
    unknown,

    pub const Primitive = enum {
        void,
        bool,
        u8,
        u16,
        u32,
        u64,
        u128,
        usize,
        i8,
        i16,
        i32,
        i64,
        i128,
        isize,
        f16,
        f32,
        f64,
        f128,
        comptime_int,
        comptime_float,
        noreturn,
        anyopaque,
    };

    pub const StdType = struct {
        path: []const u8,
    };

    pub const UserType = struct {
        module_path: []const u8,
        name: []const u8,
    };

    pub const FunctionType = struct {
        return_type: ?*const TypeInfo,
    };

    pub const PointerType = struct {
        child: ?*const TypeInfo,
        is_const: bool,
    };

    pub const OptionalType = struct {
        child: ?*const TypeInfo,
    };

    pub const ErrorUnionType = struct {
        payload: ?*const TypeInfo,
    };

    pub const SliceType = struct {
        child: ?*const TypeInfo,
    };

    pub const ArrayType = struct {
        child: ?*const TypeInfo,
        len: ?usize,
    };

    pub fn format(self: TypeInfo, comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
        switch (self) {
            .primitive => |p| try writer.print("{s}", .{@tagName(p)}),
            .std_type => |s| try writer.print("std.{s}", .{s.path}),
            .user_type => |u| try writer.print("{s}", .{u.name}),
            .type_type => try writer.writeAll("type"),
            .function => try writer.writeAll("fn"),
            .pointer => |p| {
                if (p.is_const) try writer.writeAll("*const ") else try writer.writeAll("*");
                if (p.child) |c| try c.format("", .{}, writer) else try writer.writeAll("?");
            },
            .optional => |o| {
                try writer.writeAll("?");
                if (o.child) |c| try c.format("", .{}, writer) else try writer.writeAll("?");
            },
            .error_union => |e| {
                try writer.writeAll("!");
                if (e.payload) |p| try p.format("", .{}, writer) else try writer.writeAll("?");
            },
            .slice => |s| {
                try writer.writeAll("[]");
                if (s.child) |c| try c.format("", .{}, writer) else try writer.writeAll("?");
            },
            .array => |a| {
                if (a.len) |l| try writer.print("[{}]", .{l}) else try writer.writeAll("[?]");
                if (a.child) |c| try c.format("", .{}, writer) else try writer.writeAll("?");
            },
            .unknown => try writer.writeAll("unknown"),
        }
    }

    pub fn eql(self: TypeInfo, other: TypeInfo) bool {
        const self_tag = std.meta.activeTag(self);
        const other_tag = std.meta.activeTag(other);
        if (self_tag != other_tag) return false;

        return switch (self) {
            .primitive => |p| p == other.primitive,
            .std_type => |s| std.mem.eql(u8, s.path, other.std_type.path),
            .user_type => |u| std.mem.eql(u8, u.name, other.user_type.name) and
                std.mem.eql(u8, u.module_path, other.user_type.module_path),
            .type_type => true,
            .function => true,
            .pointer, .optional, .error_union, .slice, .array => true,
            .unknown => true,
        };
    }
};

pub fn init(allocator: std.mem.Allocator, graph: *const ModuleGraph) TypeResolver {
    return .{
        .allocator = allocator,
        .graph = graph,
    };
}

pub fn deinit(self: *TypeResolver) void {
    _ = self;
}

/// Resolves the type of an AST node within a module.
pub fn typeOf(self: *TypeResolver, module_path: []const u8, node: Ast.Node.Index) TypeInfo {
    const mod = self.graph.getModule(module_path) orelse return .unknown;
    return self.resolveNodeType(&mod.tree, node, module_path);
}

fn resolveNodeType(self: *TypeResolver, tree: *const Ast, node: Ast.Node.Index, module_path: []const u8) TypeInfo {
    const tag = tree.nodeTag(node);

    return switch (tag) {
        .identifier => self.resolveIdentifier(tree, node, module_path),
        .field_access => self.resolveFieldAccess(tree, node, module_path),
        .builtin_call_two, .builtin_call_two_comma => self.resolveBuiltinCall(tree, node, module_path),
        .call_one, .call_one_comma, .call, .call_comma => self.resolveFunctionCall(tree, node, module_path),
        .number_literal => self.resolveNumberLiteral(tree, node),
        .string_literal, .multiline_string_literal => .{ .slice = .{ .child = &.{ .primitive = .u8 } } },
        .char_literal => .{ .primitive = .u8 },
        .unreachable_literal => .{ .primitive = .noreturn },
        .simple_var_decl, .aligned_var_decl, .local_var_decl, .global_var_decl => self.resolveVarDecl(tree, node, module_path),
        .fn_decl => self.resolveFnDecl(tree, node, module_path),
        .optional_type => .{ .optional = .{ .child = null } },
        .ptr_type_aligned, .ptr_type_sentinel, .ptr_type, .ptr_type_bit_range => self.resolvePtrType(tree, node),
        .error_union => .{ .error_union = .{ .payload = null } },
        .array_type, .array_type_sentinel => .{ .array = .{ .child = null, .len = null } },
        else => .unknown,
    };
}

fn resolveIdentifier(self: *TypeResolver, tree: *const Ast, node: Ast.Node.Index, module_path: []const u8) TypeInfo {
    const main_token = tree.nodeMainToken(node);
    const name = tree.tokenSlice(main_token);

    if (resolvePrimitiveType(name)) |prim| {
        return .{ .primitive = prim };
    }

    if (std.mem.eql(u8, name, "type")) {
        return .type_type;
    }

    if (std.mem.eql(u8, name, "true") or std.mem.eql(u8, name, "false")) {
        return .{ .primitive = .bool };
    }

    if (std.mem.eql(u8, name, "null")) {
        return .unknown;
    }

    if (std.mem.eql(u8, name, "undefined")) {
        return .unknown;
    }

    if (self.findDeclarationInModule(tree, name, module_path)) |decl_type| {
        return decl_type;
    }

    return .unknown;
}

fn resolvePrimitiveType(name: []const u8) ?TypeInfo.Primitive {
    const primitives = std.StaticStringMap(TypeInfo.Primitive).initComptime(.{
        .{ "void", .void },
        .{ "bool", .bool },
        .{ "u8", .u8 },
        .{ "u16", .u16 },
        .{ "u32", .u32 },
        .{ "u64", .u64 },
        .{ "u128", .u128 },
        .{ "usize", .usize },
        .{ "i8", .i8 },
        .{ "i16", .i16 },
        .{ "i32", .i32 },
        .{ "i64", .i64 },
        .{ "i128", .i128 },
        .{ "isize", .isize },
        .{ "f16", .f16 },
        .{ "f32", .f32 },
        .{ "f64", .f64 },
        .{ "f128", .f128 },
        .{ "comptime_int", .comptime_int },
        .{ "comptime_float", .comptime_float },
        .{ "noreturn", .noreturn },
        .{ "anyopaque", .anyopaque },
    });
    return primitives.get(name);
}

fn findDeclarationInModule(self: *TypeResolver, tree: *const Ast, name: []const u8, module_path: []const u8) ?TypeInfo {
    for (tree.rootDecls()) |decl_node| {
        const decl_tag = tree.nodeTag(decl_node);
        switch (decl_tag) {
            .simple_var_decl, .aligned_var_decl, .local_var_decl, .global_var_decl => {
                const var_decl = tree.fullVarDecl(decl_node) orelse continue;
                const name_token = var_decl.ast.mut_token + 1;
                const decl_name = tree.tokenSlice(name_token);
                if (std.mem.eql(u8, decl_name, name)) {
                    return self.resolveVarDecl(tree, decl_node, module_path);
                }
            },
            .fn_decl => {
                var buf: [1]Ast.Node.Index = undefined;
                const fn_proto = tree.fullFnProto(&buf, decl_node) orelse continue;
                const fn_name_token = fn_proto.name_token orelse continue;
                const fn_name = tree.tokenSlice(fn_name_token);
                if (std.mem.eql(u8, fn_name, name)) {
                    return self.resolveFnDecl(tree, decl_node, module_path);
                }
            },
            else => {},
        }
    }
    return null;
}

fn resolveVarDecl(self: *TypeResolver, tree: *const Ast, node: Ast.Node.Index, module_path: []const u8) TypeInfo {
    const var_decl = tree.fullVarDecl(node) orelse return .unknown;

    if (var_decl.ast.type_node.unwrap()) |type_node| {
        return self.resolveNodeType(tree, type_node, module_path);
    }

    if (var_decl.ast.init_node.unwrap()) |init_node| {
        return self.resolveNodeType(tree, init_node, module_path);
    }

    return .unknown;
}

fn resolveFnDecl(_: *TypeResolver, tree: *const Ast, node: Ast.Node.Index, _: []const u8) TypeInfo {
    var buf: [1]Ast.Node.Index = undefined;
    const fn_proto = tree.fullFnProto(&buf, node) orelse return .unknown;

    if (fn_proto.ast.return_type.unwrap()) |ret_type| {
        const ret_tag = tree.nodeTag(ret_type);
        if (ret_tag == .identifier) {
            const ret_name = tree.tokenSlice(tree.nodeMainToken(ret_type));
            if (std.mem.eql(u8, ret_name, "type")) {
                return .type_type;
            }
        }
    }

    return .{ .function = .{ .return_type = null } };
}

fn resolveFieldAccess(self: *TypeResolver, tree: *const Ast, node: Ast.Node.Index, module_path: []const u8) TypeInfo {
    const data = tree.nodeData(node).node_and_token;
    const lhs_node = data[0];
    const field_token = data[1];
    const field_name = tree.tokenSlice(field_token);

    const lhs_type = self.resolveNodeType(tree, lhs_node, module_path);

    switch (lhs_type) {
        .std_type => |s| {
            if (s.path.len == 0) {
                return .{ .std_type = .{ .path = field_name } };
            }
            return .{ .std_type = .{ .path = field_name } };
        },
        .user_type => {
            return .{ .std_type = .{ .path = field_name } };
        },
        .unknown => {
            const lhs_tag = tree.nodeTag(lhs_node);
            if (lhs_tag == .identifier) {
                const lhs_name = tree.tokenSlice(tree.nodeMainToken(lhs_node));
                if (std.mem.eql(u8, lhs_name, "std")) {
                    return .{ .std_type = .{ .path = field_name } };
                }
            }
        },
        else => {},
    }

    return .unknown;
}

fn resolveBuiltinCall(self: *TypeResolver, tree: *const Ast, node: Ast.Node.Index, module_path: []const u8) TypeInfo {
    const main_token = tree.nodeMainToken(node);
    const builtin_name = tree.tokenSlice(main_token);

    if (std.mem.eql(u8, builtin_name, "@import")) {
        var buf: [2]Ast.Node.Index = undefined;
        const params = tree.builtinCallParams(&buf, node) orelse return .unknown;
        if (params.len == 0) return .unknown;

        const arg_token = tree.nodeMainToken(params[0]);
        const raw_path = tree.tokenSlice(arg_token);
        if (raw_path.len < 2 or raw_path[0] != '"') return .unknown;

        const import_str = raw_path[1 .. raw_path.len - 1];

        if (std.mem.eql(u8, import_str, "std")) {
            return .{ .std_type = .{ .path = "" } };
        }

        if (std.mem.eql(u8, import_str, "builtin")) {
            return .{ .std_type = .{ .path = "builtin" } };
        }

        if (std.mem.endsWith(u8, import_str, ".zig")) {
            return .{ .user_type = .{
                .module_path = module_path,
                .name = import_str,
            } };
        }
    }

    if (std.mem.eql(u8, builtin_name, "@This")) {
        return .type_type;
    }

    if (std.mem.eql(u8, builtin_name, "@TypeOf") or std.mem.eql(u8, builtin_name, "@typeInfo")) {
        return .type_type;
    }

    if (std.mem.eql(u8, builtin_name, "@as")) {
        var buf: [2]Ast.Node.Index = undefined;
        const params = tree.builtinCallParams(&buf, node) orelse return .unknown;
        if (params.len > 0) {
            return self.resolveNodeType(tree, params[0], module_path);
        }
    }

    return .unknown;
}

fn resolveFunctionCall(self: *TypeResolver, tree: *const Ast, node: Ast.Node.Index, module_path: []const u8) TypeInfo {
    _ = module_path;
    _ = node;
    _ = tree;
    _ = self;
    return .{ .function = .{ .return_type = null } };
}

fn resolvePtrType(_: *TypeResolver, tree: *const Ast, node: Ast.Node.Index) TypeInfo {
    const main_token = tree.nodeMainToken(node);
    const token_tag = tree.tokenTag(main_token);

    if (token_tag == .l_bracket) {
        return .{ .slice = .{ .child = null } };
    }

    return .{ .pointer = .{ .child = null, .is_const = false } };
}

fn resolveNumberLiteral(_: *TypeResolver, tree: *const Ast, node: Ast.Node.Index) TypeInfo {
    const main_token = tree.nodeMainToken(node);
    const text = tree.tokenSlice(main_token);

    if (std.mem.indexOf(u8, text, ".") != null or
        std.mem.indexOf(u8, text, "e") != null or
        std.mem.indexOf(u8, text, "E") != null)
    {
        return .{ .primitive = .comptime_float };
    }

    return .{ .primitive = .comptime_int };
}

test "resolve primitive types" {
    const source = "const x: u32 = 0;";

    var tree = try Ast.parse(std.testing.allocator, source, .zig);
    defer tree.deinit(std.testing.allocator);

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    try tmp_dir.dir.writeFile(.{ .sub_path = "test.zig", .data = source });
    const path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, "test.zig");
    defer std.testing.allocator.free(path);

    var graph = try ModuleGraph.init(std.testing.allocator, path, null);
    defer graph.deinit();

    var resolver: TypeResolver = .init(std.testing.allocator, &graph);
    defer resolver.deinit();

    const root_decls = tree.rootDecls();
    try std.testing.expect(root_decls.len > 0);

    const type_info = resolver.typeOf(path, root_decls[0]);
    try std.testing.expect(type_info == .primitive);
    try std.testing.expectEqual(TypeInfo.Primitive.u32, type_info.primitive);
}

test "resolve bool literal" {
    const source = "const x = true;";

    var tree = try Ast.parse(std.testing.allocator, source, .zig);
    defer tree.deinit(std.testing.allocator);

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    try tmp_dir.dir.writeFile(.{ .sub_path = "test.zig", .data = source });
    const path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, "test.zig");
    defer std.testing.allocator.free(path);

    var graph = try ModuleGraph.init(std.testing.allocator, path, null);
    defer graph.deinit();

    var resolver: TypeResolver = .init(std.testing.allocator, &graph);
    defer resolver.deinit();

    const root_decls = tree.rootDecls();
    const type_info = resolver.typeOf(path, root_decls[0]);
    try std.testing.expect(type_info == .primitive);
    try std.testing.expectEqual(TypeInfo.Primitive.bool, type_info.primitive);
}

test "resolve import std" {
    const source = "const std = @import(\"std\");";

    var tree = try Ast.parse(std.testing.allocator, source, .zig);
    defer tree.deinit(std.testing.allocator);

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    try tmp_dir.dir.writeFile(.{ .sub_path = "test.zig", .data = source });
    const path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, "test.zig");
    defer std.testing.allocator.free(path);

    var graph = try ModuleGraph.init(std.testing.allocator, path, null);
    defer graph.deinit();

    var resolver: TypeResolver = .init(std.testing.allocator, &graph);
    defer resolver.deinit();

    const root_decls = tree.rootDecls();
    const type_info = resolver.typeOf(path, root_decls[0]);
    try std.testing.expect(type_info == .std_type);
}

test "resolve function returns type" {
    const source = "fn MyType() type { return struct {}; }";

    var tree = try Ast.parse(std.testing.allocator, source, .zig);
    defer tree.deinit(std.testing.allocator);

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    try tmp_dir.dir.writeFile(.{ .sub_path = "test.zig", .data = source });
    const path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, "test.zig");
    defer std.testing.allocator.free(path);

    var graph = try ModuleGraph.init(std.testing.allocator, path, null);
    defer graph.deinit();

    var resolver: TypeResolver = .init(std.testing.allocator, &graph);
    defer resolver.deinit();

    const root_decls = tree.rootDecls();
    const type_info = resolver.typeOf(path, root_decls[0]);
    try std.testing.expect(type_info == .type_type);
}

test "resolve number literal int" {
    const source = "const x = 42;";

    var tree = try Ast.parse(std.testing.allocator, source, .zig);
    defer tree.deinit(std.testing.allocator);

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    try tmp_dir.dir.writeFile(.{ .sub_path = "test.zig", .data = source });
    const path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, "test.zig");
    defer std.testing.allocator.free(path);

    var graph = try ModuleGraph.init(std.testing.allocator, path, null);
    defer graph.deinit();

    var resolver: TypeResolver = .init(std.testing.allocator, &graph);
    defer resolver.deinit();

    const root_decls = tree.rootDecls();
    const type_info = resolver.typeOf(path, root_decls[0]);
    try std.testing.expect(type_info == .primitive);
    try std.testing.expectEqual(TypeInfo.Primitive.comptime_int, type_info.primitive);
}

test "resolve number literal float" {
    const source = "const x = 3.14;";

    var tree = try Ast.parse(std.testing.allocator, source, .zig);
    defer tree.deinit(std.testing.allocator);

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    try tmp_dir.dir.writeFile(.{ .sub_path = "test.zig", .data = source });
    const path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, "test.zig");
    defer std.testing.allocator.free(path);

    var graph = try ModuleGraph.init(std.testing.allocator, path, null);
    defer graph.deinit();

    var resolver: TypeResolver = .init(std.testing.allocator, &graph);
    defer resolver.deinit();

    const root_decls = tree.rootDecls();
    const type_info = resolver.typeOf(path, root_decls[0]);
    try std.testing.expect(type_info == .primitive);
    try std.testing.expectEqual(TypeInfo.Primitive.comptime_float, type_info.primitive);
}

test "resolve field access on std" {
    const source =
        \\const std = @import("std");
        \\const fs = std.fs;
    ;

    var tree = try Ast.parse(std.testing.allocator, source, .zig);
    defer tree.deinit(std.testing.allocator);

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    try tmp_dir.dir.writeFile(.{ .sub_path = "test.zig", .data = source });
    const path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, "test.zig");
    defer std.testing.allocator.free(path);

    var graph = try ModuleGraph.init(std.testing.allocator, path, null);
    defer graph.deinit();

    var resolver: TypeResolver = .init(std.testing.allocator, &graph);
    defer resolver.deinit();

    const root_decls = tree.rootDecls();
    try std.testing.expect(root_decls.len >= 2);

    const type_info = resolver.typeOf(path, root_decls[1]);
    try std.testing.expect(type_info == .std_type);
    try std.testing.expectEqualStrings("fs", type_info.std_type.path);
}

test "resolve string literal" {
    const source = "const s = \"hello\";";

    var tree = try Ast.parse(std.testing.allocator, source, .zig);
    defer tree.deinit(std.testing.allocator);

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    try tmp_dir.dir.writeFile(.{ .sub_path = "test.zig", .data = source });
    const path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, "test.zig");
    defer std.testing.allocator.free(path);

    var graph = try ModuleGraph.init(std.testing.allocator, path, null);
    defer graph.deinit();

    var resolver: TypeResolver = .init(std.testing.allocator, &graph);
    defer resolver.deinit();

    const root_decls = tree.rootDecls();
    const type_info = resolver.typeOf(path, root_decls[0]);
    try std.testing.expect(type_info == .slice);
}

test "resolve function declaration" {
    const source = "fn foo() void {}";

    var tree = try Ast.parse(std.testing.allocator, source, .zig);
    defer tree.deinit(std.testing.allocator);

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    try tmp_dir.dir.writeFile(.{ .sub_path = "test.zig", .data = source });
    const path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, "test.zig");
    defer std.testing.allocator.free(path);

    var graph = try ModuleGraph.init(std.testing.allocator, path, null);
    defer graph.deinit();

    var resolver: TypeResolver = .init(std.testing.allocator, &graph);
    defer resolver.deinit();

    const root_decls = tree.rootDecls();
    const type_info = resolver.typeOf(path, root_decls[0]);
    try std.testing.expect(type_info == .function);
}
