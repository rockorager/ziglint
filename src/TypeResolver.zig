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
    /// An error set type (error{A, B, C})
    error_set,
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

pub const MethodDef = struct {
    module_path: []const u8,
    node: Ast.Node.Index,
    name_token: Ast.TokenIndex,
    line: u32,
    column: u32,
};

pub fn deinit(self: *TypeResolver) void {
    _ = self;
}

/// Resolves the type of an AST node within a module.
pub fn typeOf(self: *TypeResolver, module_path: []const u8, node: Ast.Node.Index) TypeInfo {
    const mod = self.graph.getModule(module_path) orelse return .unknown;
    return self.resolveNodeType(&mod.tree, node, module_path);
}

/// Finds a method definition given a receiver type and method name.
/// For user_type, looks up the method in the type's module.
/// For std_type, resolves the path through stdlib imports to find the type.
pub fn findMethodDef(self: *TypeResolver, receiver_type: TypeInfo, method_name: []const u8) ?MethodDef {
    switch (receiver_type) {
        .user_type => |u| {
            return self.findMethodInModule(u.module_path, u.name, method_name);
        },
        .std_type => |s| {
            return self.findMethodInStdlib(s.path, method_name);
        },
        else => return null,
    }
}

/// Resolves a stdlib path like "fs.File" to find the method.
/// Follows the import chain: std.zig -> fs.zig -> File type -> method
fn findMethodInStdlib(self: *TypeResolver, path: []const u8, method_name: []const u8) ?MethodDef {
    const lib_path = self.graph.zig_lib_path orelse return null;

    // Start at std.zig (lib_dir/std/std.zig)
    const std_path = std.fs.path.join(self.allocator, &.{ lib_path, "std", "std.zig" }) catch return null;
    defer self.allocator.free(std_path);

    // Split path into components (e.g., "fs.File" -> ["fs", "File"])
    var components = std.mem.splitScalar(u8, path, '.');
    var current_module_path: []const u8 = std_path;
    var owns_path = false;
    defer if (owns_path) self.allocator.free(current_module_path);

    var type_name: ?[]const u8 = null;

    while (components.next()) |component| {
        const mod = self.graph.getModule(current_module_path) orelse return null;
        const tree = &mod.tree;

        // Look for this component as a declaration
        if (self.findDeclInModule(tree, component, current_module_path)) |result| {
            switch (result) {
                .import_path => |imported| {
                    // It's an import, follow it
                    if (owns_path) self.allocator.free(current_module_path);
                    current_module_path = imported;
                    owns_path = true;
                },
                .type_node => {
                    // It's a type declaration, this should be the last component
                    type_name = component;
                    break;
                },
            }
        } else {
            return null;
        }
    }

    // If we have a type name, look for the method in that type
    if (type_name) |tn| {
        return self.findMethodInModule(current_module_path, tn, method_name);
    }

    // No explicit type - the module itself might be a file-as-struct (like fs/File.zig)
    return self.findMethodInFileAsStruct(current_module_path, method_name);
}

const DeclResult = union(enum) {
    import_path: []const u8,
    type_node: Ast.Node.Index,
};

/// Finds a declaration in a module and returns either an import path or type node.
fn findDeclInModule(self: *TypeResolver, tree: *const Ast, name: []const u8, module_path: []const u8) ?DeclResult {
    for (tree.rootDecls()) |decl_node| {
        const decl_tag = tree.nodeTag(decl_node);
        switch (decl_tag) {
            .simple_var_decl, .aligned_var_decl, .local_var_decl, .global_var_decl => {
                const var_decl = tree.fullVarDecl(decl_node) orelse continue;
                const name_token = var_decl.ast.mut_token + 1;
                const decl_name = tree.tokenSlice(name_token);
                if (!std.mem.eql(u8, decl_name, name)) continue;

                const init_node = var_decl.ast.init_node.unwrap() orelse continue;
                const init_tag = tree.nodeTag(init_node);

                // Check if it's an @import
                if (init_tag == .builtin_call_two or init_tag == .builtin_call_two_comma) {
                    const main_token = tree.nodeMainToken(init_node);
                    const builtin_name = tree.tokenSlice(main_token);
                    if (std.mem.eql(u8, builtin_name, "@import")) {
                        var buf: [2]Ast.Node.Index = undefined;
                        const params = tree.builtinCallParams(&buf, init_node) orelse continue;
                        if (params.len == 0) continue;

                        const arg_token = tree.nodeMainToken(params[0]);
                        const raw_path = tree.tokenSlice(arg_token);
                        if (raw_path.len < 2 or raw_path[0] != '"') continue;

                        const import_str = raw_path[1 .. raw_path.len - 1];
                        if (std.mem.endsWith(u8, import_str, ".zig")) {
                            const module_dir = std.fs.path.dirname(module_path) orelse ".";
                            const resolved = std.fs.path.join(self.allocator, &.{ module_dir, import_str }) catch continue;
                            const canonical = std.fs.cwd().realpathAlloc(self.allocator, resolved) catch {
                                self.allocator.free(resolved);
                                continue;
                            };
                            self.allocator.free(resolved);
                            return .{ .import_path = canonical };
                        }
                    }
                }

                // It's a type declaration
                if (isContainerDecl(init_tag)) {
                    return .{ .type_node = init_node };
                }
            },
            else => {},
        }
    }
    return null;
}

fn findMethodInModule(self: *TypeResolver, module_path: []const u8, type_name: []const u8, method_name: []const u8) ?MethodDef {
    const mod = self.graph.getModule(module_path) orelse return null;
    const tree = &mod.tree;

    const type_node = self.findTypeDecl(tree, type_name) orelse return null;

    return self.findMethodInType(tree, type_node, method_name, module_path);
}

/// For file-as-struct modules (like fs/File.zig), look for methods in root declarations.
fn findMethodInFileAsStruct(self: *TypeResolver, module_path: []const u8, method_name: []const u8) ?MethodDef {
    const mod = self.graph.getModule(module_path) orelse return null;
    const tree = &mod.tree;

    for (tree.rootDecls()) |decl| {
        const tag = tree.nodeTag(decl);
        if (tag == .fn_decl) {
            var buf: [1]Ast.Node.Index = undefined;
            const fn_proto = tree.fullFnProto(&buf, decl) orelse continue;
            const fn_name_token = fn_proto.name_token orelse continue;
            const fn_name = tree.tokenSlice(fn_name_token);
            if (std.mem.eql(u8, fn_name, method_name)) {
                const loc = tree.tokenLocation(0, fn_name_token);
                return .{
                    .module_path = mod.path,
                    .node = decl,
                    .name_token = fn_name_token,
                    .line = @intCast(loc.line),
                    .column = @intCast(loc.column),
                };
            }
        }
    }
    return null;
}

fn findTypeDecl(self: *TypeResolver, tree: *const Ast, type_name: []const u8) ?Ast.Node.Index {
    _ = self;

    for (tree.rootDecls()) |decl_node| {
        const decl_tag = tree.nodeTag(decl_node);
        switch (decl_tag) {
            .simple_var_decl, .aligned_var_decl, .local_var_decl, .global_var_decl => {
                const var_decl = tree.fullVarDecl(decl_node) orelse continue;
                const name_token = var_decl.ast.mut_token + 1;
                const decl_name = tree.tokenSlice(name_token);
                if (std.mem.eql(u8, decl_name, type_name)) {
                    const init_node = var_decl.ast.init_node.unwrap() orelse continue;
                    return init_node;
                }
            },
            else => {},
        }
    }
    return null;
}

fn findMethodInType(self: *TypeResolver, tree: *const Ast, type_node: Ast.Node.Index, method_name: []const u8, module_path: []const u8) ?MethodDef {
    _ = self;

    const tag = tree.nodeTag(type_node);

    var members_buf: [2]Ast.Node.Index = undefined;
    const members: []const Ast.Node.Index = switch (tag) {
        .container_decl, .container_decl_trailing => blk: {
            const data = tree.nodeData(type_node).extra_range;
            const start: usize = @intFromEnum(data.start);
            const end: usize = @intFromEnum(data.end);
            break :blk @ptrCast(tree.extra_data[start..end]);
        },
        .container_decl_two, .container_decl_two_trailing => blk: {
            const data = tree.nodeData(type_node).opt_node_and_opt_node;
            var len: usize = 0;
            if (data[0].unwrap()) |n| {
                members_buf[len] = n;
                len += 1;
            }
            if (data[1].unwrap()) |n| {
                members_buf[len] = n;
                len += 1;
            }
            break :blk members_buf[0..len];
        },
        else => return null,
    };

    for (members) |member| {
        const member_tag = tree.nodeTag(member);
        if (member_tag == .fn_decl) {
            var buf: [1]Ast.Node.Index = undefined;
            const fn_proto = tree.fullFnProto(&buf, member) orelse continue;
            const fn_name_token = fn_proto.name_token orelse continue;
            const fn_name = tree.tokenSlice(fn_name_token);
            if (std.mem.eql(u8, fn_name, method_name)) {
                const loc = tree.tokenLocation(0, fn_name_token);
                return .{
                    .module_path = module_path,
                    .node = member,
                    .name_token = fn_name_token,
                    .line = @intCast(loc.line),
                    .column = @intCast(loc.column),
                };
            }
        }
    }

    return null;
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
        .error_set_decl => .error_set,
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
                    return self.resolveVarDeclWithName(tree, decl_node, module_path, decl_name);
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
    const name_token = var_decl.ast.mut_token + 1;
    const name = tree.tokenSlice(name_token);
    return self.resolveVarDeclWithName(tree, node, module_path, name);
}

fn resolveVarDeclWithName(self: *TypeResolver, tree: *const Ast, node: Ast.Node.Index, module_path: []const u8, decl_name: []const u8) TypeInfo {
    const var_decl = tree.fullVarDecl(node) orelse return .unknown;

    if (var_decl.ast.type_node.unwrap()) |type_node| {
        return self.resolveNodeType(tree, type_node, module_path);
    }

    if (var_decl.ast.init_node.unwrap()) |init_node| {
        const init_tag = tree.nodeTag(init_node);
        if (isContainerDecl(init_tag)) {
            return .{ .user_type = .{ .module_path = module_path, .name = decl_name } };
        }
        return self.resolveNodeType(tree, init_node, module_path);
    }

    return .unknown;
}

fn isContainerDecl(tag: Ast.Node.Tag) bool {
    return switch (tag) {
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
            // Build the full path: "fs" + "." + "File" = "fs.File"
            if (s.path.len == 0) {
                return .{ .std_type = .{ .path = field_name } };
            }
            // Concatenate paths - we store these as slices into source, so we
            // need to build a path string. For now, return the accumulated path
            // by looking at the full field access chain.
            const full_path = self.buildStdTypePath(tree, node);
            return .{ .std_type = .{ .path = full_path } };
        },
        .user_type => {
            // Accessing a field on a user type - could be a nested type
            const full_path = self.buildStdTypePath(tree, node);
            return .{ .std_type = .{ .path = full_path } };
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

/// Builds the full path for a std type by walking up the field access chain.
/// For `std.fs.File`, returns "fs.File".
fn buildStdTypePath(self: *TypeResolver, tree: *const Ast, node: Ast.Node.Index) []const u8 {
    _ = self;
    var parts: [16][]const u8 = undefined;
    var count: usize = 0;

    var current = node;
    while (count < 16) {
        const tag = tree.nodeTag(current);
        if (tag != .field_access) break;

        const data = tree.nodeData(current).node_and_token;
        const field_token = data[1];
        parts[count] = tree.tokenSlice(field_token);
        count += 1;
        current = data[0];
    }

    if (count == 0) return "";

    // Check if root is "std"
    const root_tag = tree.nodeTag(current);
    if (root_tag == .identifier) {
        const root_name = tree.tokenSlice(tree.nodeMainToken(current));
        if (!std.mem.eql(u8, root_name, "std")) {
            return "";
        }
    }

    // Reverse and join - parts are in reverse order
    // For simplicity, just return the last part which is the type name
    // The full path is used for resolution
    if (count >= 1) {
        // Build path from parts in reverse order, skipping the type name at index 0
        // e.g., for std.fs.File: parts = ["File", "fs"], we want "fs.File"
        // For now, return the joined path from the source directly
        // Since we can't easily allocate, we'll use a different approach:
        // Return the full path by computing byte range in source
        const first_token = tree.nodeMainToken(node);
        const last_data = tree.nodeData(node).node_and_token;
        _ = last_data;

        // Find the start of the path after "std."
        var start_node = node;
        while (tree.nodeTag(start_node) == .field_access) {
            const d = tree.nodeData(start_node).node_and_token;
            const lhs = d[0];
            if (tree.nodeTag(lhs) == .identifier) {
                const lhs_name = tree.tokenSlice(tree.nodeMainToken(lhs));
                if (std.mem.eql(u8, lhs_name, "std")) {
                    break;
                }
            }
            start_node = lhs;
        }

        // Get the token after "std."
        if (tree.nodeTag(start_node) == .field_access) {
            const start_data = tree.nodeData(start_node).node_and_token;
            const start_field_token = start_data[1];
            const end_field_token = first_token;
            _ = end_field_token;

            // Get byte positions
            const start_loc = tree.tokenLocation(0, start_field_token);
            const end_token_data = tree.nodeData(node).node_and_token;
            const end_loc = tree.tokenLocation(0, end_token_data[1]);
            const end_slice = tree.tokenSlice(end_token_data[1]);

            const start_byte = start_loc.line_start + start_loc.column;
            const end_byte = end_loc.line_start + end_loc.column + end_slice.len;

            if (end_byte > start_byte and end_byte <= tree.source.len) {
                return tree.source[start_byte..end_byte];
            }
        }
    }

    return parts[0];
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

test "resolve nested field access std.fs.File" {
    const source =
        \\const std = @import("std");
        \\const File = std.fs.File;
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
    try std.testing.expectEqualStrings("fs.File", type_info.std_type.path);
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

test "find method in user type" {
    const source =
        \\const MyType = struct {
        \\    value: u32,
        \\    pub fn getValue(self: *@This()) u32 {
        \\        return self.value;
        \\    }
        \\};
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

    const user_type: TypeInfo = .{ .user_type = .{ .module_path = path, .name = "MyType" } };
    const method_def = resolver.findMethodDef(user_type, "getValue");

    try std.testing.expect(method_def != null);
    try std.testing.expectEqual(@as(u32, 2), method_def.?.line);
}

test "find method not found returns null" {
    const source =
        \\const MyType = struct {
        \\    value: u32,
        \\};
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

    const user_type: TypeInfo = .{ .user_type = .{ .module_path = path, .name = "MyType" } };
    const method_def = resolver.findMethodDef(user_type, "nonexistent");

    try std.testing.expect(method_def == null);
}

test "find method in std_type without zig_lib_path returns null" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    try tmp_dir.dir.writeFile(.{ .sub_path = "test.zig", .data = "const x = 1;" });
    const path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, "test.zig");
    defer std.testing.allocator.free(path);

    // No zig_lib_path, so stdlib can't be resolved
    var graph = try ModuleGraph.init(std.testing.allocator, path, null);
    defer graph.deinit();

    var resolver: TypeResolver = .init(std.testing.allocator, &graph);
    defer resolver.deinit();

    const std_type: TypeInfo = .{ .std_type = .{ .path = "fs.File" } };
    const method_def = resolver.findMethodDef(std_type, "read");

    try std.testing.expect(method_def == null);
}
