//! Core linter that parses Zig source and runs lint rules.

const std = @import("std");
const Ast = std.zig.Ast;
const rules = @import("rules.zig");
const TypeResolver = @import("TypeResolver.zig");
const doc_comments = @import("doc_comments.zig");
const Config = @import("Config.zig");

pub const DeprecationKey = struct {
    module_path_hash: u64,
    node: Ast.Node.Index,

    pub fn init(module_path: []const u8, node: Ast.Node.Index) DeprecationKey {
        return .{
            .module_path_hash = std.hash.Wyhash.hash(0, module_path),
            .node = node,
        };
    }
};

const Linter = @This();

allocator: std.mem.Allocator,
source: [:0]const u8,
path: []const u8,
tree: Ast,
diagnostics: std.ArrayList(Diagnostic),
seen_imports: std.StringHashMapUnmanaged(Ast.TokenIndex),
type_resolver: ?*TypeResolver = null,
module_path: ?[]const u8 = null,
config: *const Config = &default_config,
allocated_contexts: std.ArrayList([]const u8) = .empty,
public_types: std.StringHashMapUnmanaged(void) = .empty,
imported_types: std.StringHashMapUnmanaged(void) = .empty,
import_bindings: std.StringHashMapUnmanaged(ImportInfo) = .empty,
used_identifiers: std.StringHashMapUnmanaged(void) = .empty,
current_fn_return_type: Ast.Node.OptionalIndex = .none,
parent_map: []Ast.Node.OptionalIndex = &.{},
/// Cache of (module_path, node) -> is_deprecated to avoid re-parsing doc comments
deprecation_cache: std.AutoHashMapUnmanaged(DeprecationKey, bool) = .empty,

const default_config: Config = .{};

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

pub fn init(allocator: std.mem.Allocator, source: [:0]const u8, path: []const u8, config: ?*const Config) Linter {
    return .{
        .allocator = allocator,
        .source = source,
        .path = path,
        .tree = Ast.parse(allocator, source, .zig) catch unreachable,
        .diagnostics = .empty,
        .seen_imports = .empty,
        .config = config orelse &default_config,
    };
}

pub fn initWithSemantics(
    allocator: std.mem.Allocator,
    source: [:0]const u8,
    path: []const u8,
    type_resolver: *TypeResolver,
    module_path: []const u8,
    config: ?*const Config,
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
        .config = config orelse &default_config,
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
    self.deprecation_cache.deinit(self.allocator);
    if (self.parent_map.len > 0) {
        self.allocator.free(self.parent_map);
    }
    self.* = undefined;
}

pub fn lint(self: *Linter) void {
    self.checkParseErrors();
    if (self.tree.errors.len > 0) return;

    self.checkLineLength();
    self.checkFileAsStruct();
    self.buildPublicTypesMap();
    self.collectAllIdentifiers();
    self.buildParentMap();

    for (self.tree.rootDecls()) |node| {
        self.visitNode(node);
    }

    self.checkUnusedImports();
    self.checkThisBuiltin();
    self.checkInlineImports();
    self.checkCatchReturnAll();
    self.checkEmptyCatchAll();
    self.checkInstanceDeclAccess();
}

fn collectAllIdentifiers(self: *Linter) void {
    for (0..self.tree.nodes.len) |i| {
        const node: Ast.Node.Index = @enumFromInt(i);
        const tag = self.tree.nodeTag(node);
        switch (tag) {
            .identifier => {
                const name = self.tree.tokenSlice(self.tree.nodeMainToken(node));
                // ziglint-ignore: Z026
                self.used_identifiers.put(self.allocator, name, {}) catch {};
            },
            .field_access => {
                // Walk field_access chain, tracking all field names and root identifier
                var current = node;
                while (self.tree.nodeTag(current) == .field_access) {
                    const data = self.tree.nodeData(current).node_and_token;
                    const field_name = self.tree.tokenSlice(data[1]);
                    // ziglint-ignore: Z026
                    self.used_identifiers.put(self.allocator, field_name, {}) catch {};
                    current = data[0];
                }
                if (self.tree.nodeTag(current) == .identifier) {
                    const name = self.tree.tokenSlice(self.tree.nodeMainToken(current));
                    // ziglint-ignore: Z026
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

fn buildParentMap(self: *Linter) void {
    self.parent_map = self.allocator.alloc(Ast.Node.OptionalIndex, self.tree.nodes.len) catch return;
    @memset(self.parent_map, .none);

    for (0..self.tree.nodes.len) |i| {
        const node: Ast.Node.Index = @enumFromInt(i);

        // Handle nodes with potentially many children directly
        const tag = self.tree.nodeTag(node);
        switch (tag) {
            .block, .block_semicolon => {
                var buf: [2]Ast.Node.Index = undefined;
                const stmts = self.tree.blockStatements(&buf, node) orelse continue;
                for (stmts) |stmt| {
                    self.parent_map[@intFromEnum(stmt)] = node.toOptional();
                }
                continue;
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
            => {
                var buf: [2]Ast.Node.Index = undefined;
                const container = self.tree.fullContainerDecl(&buf, node) orelse continue;
                for (container.ast.members) |member| {
                    self.parent_map[@intFromEnum(member)] = node.toOptional();
                }
                continue;
            },
            else => {},
        }

        // Use ChildList for nodes with bounded children
        const children = self.getNodeChildren(node);
        for (children.slice()) |child| {
            self.parent_map[@intFromEnum(child)] = node.toOptional();
        }
    }
}

const ChildList = struct {
    items: [8]Ast.Node.Index = undefined,
    len: usize = 0,

    fn append(self: *ChildList, item: Ast.Node.Index) void {
        if (self.len < 8) {
            self.items[self.len] = item;
            self.len += 1;
        }
    }

    fn slice(self: *const ChildList) []const Ast.Node.Index {
        return self.items[0..self.len];
    }
};

fn getNodeChildren(self: *Linter, node: Ast.Node.Index) ChildList {
    var children: ChildList = .{};
    const tag = self.tree.nodeTag(node);

    switch (tag) {
        // fn_decl: node_and_node = [fn_proto, body]
        .fn_decl => {
            const pair = self.tree.nodeData(node).node_and_node;
            children.append(pair[0]);
            children.append(pair[1]);
        },

        // test_decl: opt_token_and_node = [name_token, block]
        .test_decl => {
            const data = self.tree.nodeData(node).opt_token_and_node;
            children.append(data[1]);
        },

        // Var decl types - use fullVarDecl for safe access
        .simple_var_decl, .aligned_var_decl, .local_var_decl, .global_var_decl => {
            const var_decl = self.tree.fullVarDecl(node) orelse return children;
            if (var_decl.ast.type_node.unwrap()) |n| children.append(n);
            if (var_decl.ast.init_node.unwrap()) |n| children.append(n);
        },

        // Builtin calls - opt_node_and_opt_node
        .builtin_call_two, .builtin_call_two_comma => {
            const data = self.tree.nodeData(node).opt_node_and_opt_node;
            if (data[0].unwrap()) |n| children.append(n);
            if (data[1].unwrap()) |n| children.append(n);
        },

        // Container declarations (structs, enums, unions) - use fullContainerDecl for safe access
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
        => {
            var buf: [2]Ast.Node.Index = undefined;
            const container = self.tree.fullContainerDecl(&buf, node) orelse return children;
            for (container.ast.members) |member| {
                children.append(member);
            }
        },

        // Block - use blockStatements for safe access
        .block, .block_semicolon => {
            var buf: [2]Ast.Node.Index = undefined;
            const stmts = self.tree.blockStatements(&buf, node) orelse return children;
            for (stmts) |stmt| children.append(stmt);
        },

        .block_two, .block_two_semicolon => {
            const data = self.tree.nodeData(node).opt_node_and_opt_node;
            if (data[0].unwrap()) |n| children.append(n);
            if (data[1].unwrap()) |n| children.append(n);
        },

        // If expressions
        .if_simple, .@"if" => {
            const full_if = self.tree.fullIf(node) orelse return children;
            children.append(full_if.ast.cond_expr);
            children.append(full_if.ast.then_expr);
            if (full_if.ast.else_expr.unwrap()) |n| children.append(n);
        },

        // While loops
        .while_simple, .while_cont, .@"while" => {
            const full_while = self.tree.fullWhile(node) orelse return children;
            children.append(full_while.ast.cond_expr);
            children.append(full_while.ast.then_expr);
            if (full_while.ast.else_expr.unwrap()) |n| children.append(n);
        },

        // For loops
        .for_simple, .@"for" => {
            const full_for = self.tree.fullFor(node) orelse return children;
            children.append(full_for.ast.then_expr);
            if (full_for.ast.else_expr.unwrap()) |n| children.append(n);
        },

        .@"defer" => {
            children.append(self.tree.nodeData(node).node);
        },

        .@"errdefer" => {
            const data = self.tree.nodeData(node).opt_token_and_node;
            children.append(data[1]);
        },

        // field_access: node_and_token = [lhs, field_token]
        .field_access => {
            const data = self.tree.nodeData(node).node_and_token;
            children.append(data[0]);
        },

        // assign: node_and_node = [lhs, rhs]
        .assign => {
            const data = self.tree.nodeData(node).node_and_node;
            children.append(data[0]);
            children.append(data[1]);
        },

        // call_one: node_and_opt_node = [callee, arg]
        .call_one, .call_one_comma => {
            const data = self.tree.nodeData(node).node_and_opt_node;
            children.append(data[0]);
            if (data[1].unwrap()) |arg| children.append(arg);
        },

        // call: sub_range = [callee, args...]
        .call, .call_comma => {
            var buf: [1]Ast.Node.Index = undefined;
            const full_call = self.tree.fullCall(&buf, node) orelse return children;
            children.append(full_call.ast.fn_expr);
            for (full_call.ast.params) |param| children.append(param);
        },

        // try: node = [inner_expr]
        .@"try" => {
            children.append(self.tree.nodeData(node).node);
        },

        // catch: node_and_node = [lhs, rhs]
        .@"catch" => {
            const data = self.tree.nodeData(node).node_and_node;
            children.append(data[0]); // The expression being caught
            children.append(data[1]); // The catch body
        },

        else => {},
    }

    return children;
}

fn checkThisBuiltin(self: *Linter) void {
    for (0..self.tree.nodes.len) |i| {
        const node: Ast.Node.Index = @enumFromInt(i);
        const tag = self.tree.nodeTag(node);

        // Look for @This() calls
        if (tag != .builtin_call_two and tag != .builtin_call_two_comma) continue;
        const main_token = self.tree.nodeMainToken(node);
        const builtin_name = self.tree.tokenSlice(main_token);
        if (!std.mem.eql(u8, builtin_name, "@This")) continue;

        // Found @This() - check if it's valid
        const loc = self.tree.tokenLocation(0, main_token);

        // Check 1: Is it in the form `const X = @This();`?
        const parent = self.parent_map[@intFromEnum(node)].unwrap() orelse {
            // Z020: inline @This()
            self.report(loc, .Z020, "");
            continue;
        };

        const parent_tag = self.tree.nodeTag(parent);

        // Allow @This() as a function argument (e.g., testing.refAllDecls(@This()))
        if (parent_tag == .call_one or parent_tag == .call_one_comma or
            parent_tag == .call or parent_tag == .call_comma)
        {
            continue;
        }

        const const_decl_info: ?struct { name: []const u8 } = switch (parent_tag) {
            .simple_var_decl, .aligned_var_decl, .local_var_decl, .global_var_decl => blk: {
                const var_decl = self.tree.fullVarDecl(parent) orelse break :blk null;
                const mut_token = self.tree.tokenSlice(var_decl.ast.mut_token);
                const init_node = var_decl.ast.init_node.unwrap() orelse break :blk null;
                if (!std.mem.eql(u8, mut_token, "const") or init_node != node) break :blk null;
                const name_token = var_decl.ast.mut_token + 1;
                break :blk .{ .name = self.tree.tokenSlice(name_token) };
            },
            else => null,
        };

        if (const_decl_info == null) {
            // Z020: inline @This()
            self.report(loc, .Z020, "");
            continue;
        }

        const alias_name = const_decl_info.?.name;

        // Check 2: Is the enclosing struct anonymous?
        const struct_name = self.findEnclosingStructName(node);
        if (struct_name) |name| {
            // Z019: @This() in named struct
            self.report(loc, .Z019, name);
            continue;
        }

        // Check 3: If at file level, alias should match filename or be Self
        if (self.isAtFileLevel(node)) {
            const basename = std.fs.path.basename(self.path);
            const expected = if (std.mem.endsWith(u8, basename, ".zig"))
                basename[0 .. basename.len - 4]
            else
                basename;

            // Allow "Self" or the filename (case-insensitive)
            const is_self = std.mem.eql(u8, alias_name, "Self");
            const matches_filename = std.ascii.eqlIgnoreCase(alias_name, expected);
            if (!is_self and !matches_filename) {
                // Z021: alias doesn't match filename or Self (only for file-as-struct)
                if (self.hasTopLevelFields()) {
                    const context = self.allocator.alloc(u8, alias_name.len + 1 + expected.len) catch continue;
                    @memcpy(context[0..alias_name.len], alias_name);
                    context[alias_name.len] = 0;
                    @memcpy(context[alias_name.len + 1 ..], expected);
                    // ziglint-ignore: Z026
                    self.allocated_contexts.append(self.allocator, context) catch {};
                    self.report(loc, .Z021, context);
                }
            }
        } else {
            // Check 4: In anonymous/local struct, alias must be "Self"
            if (!std.mem.eql(u8, alias_name, "Self")) {
                self.report(loc, .Z022, alias_name);
            }
        }
    }
}

fn checkInlineImports(self: *Linter) void {
    if (!self.config.isRuleEnabled(.Z028)) return;

    for (0..self.tree.nodes.len) |i| {
        const node: Ast.Node.Index = @enumFromInt(i);
        const tag = self.tree.nodeTag(node);

        // Look for @import() calls
        if (tag != .builtin_call_two and tag != .builtin_call_two_comma) continue;
        const main_token = self.tree.nodeMainToken(node);
        const builtin_name = self.tree.tokenSlice(main_token);
        if (!std.mem.eql(u8, builtin_name, "@import")) continue;

        // Walk up through field_access chain to find var decl
        // e.g., `const Rule = @import("rules.zig").Rule;`
        var current = node;
        while (true) {
            const parent = self.parent_map[@intFromEnum(current)].unwrap() orelse {
                const loc = self.tree.tokenLocation(0, main_token);
                self.report(loc, .Z028, "");
                break;
            };

            const parent_tag = self.tree.nodeTag(parent);
            switch (parent_tag) {
                .field_access => {
                    // Continue walking up through field access chain
                    current = parent;
                    continue;
                },
                .simple_var_decl, .aligned_var_decl, .local_var_decl, .global_var_decl => {
                    const var_decl = self.tree.fullVarDecl(parent) orelse {
                        const loc = self.tree.tokenLocation(0, main_token);
                        self.report(loc, .Z028, "");
                        break;
                    };
                    const mut_token = self.tree.tokenSlice(var_decl.ast.mut_token);
                    const init_node = var_decl.ast.init_node.unwrap() orelse {
                        const loc = self.tree.tokenLocation(0, main_token);
                        self.report(loc, .Z028, "");
                        break;
                    };
                    // Must be `const` and the init must be our current node (or an ancestor)
                    if (!std.mem.eql(u8, mut_token, "const") or init_node != current) {
                        const loc = self.tree.tokenLocation(0, main_token);
                        self.report(loc, .Z028, "");
                        break;
                    }
                    // Check that the var decl is at file level (not inside a function)
                    // Allow imports in test blocks
                    if (!self.isAtFileLevel(parent) and !self.isInTestBlock(parent)) {
                        const loc = self.tree.tokenLocation(0, main_token);
                        self.report(loc, .Z028, "");
                    }
                    break;
                },
                .assign => {
                    // Allow `_ = @import(...)` pattern for pulling in tests
                    const data = self.tree.nodeData(parent).node_and_node;
                    const lhs = data[0];
                    if (self.tree.nodeTag(lhs) == .identifier) {
                        const lhs_name = self.tree.tokenSlice(self.tree.nodeMainToken(lhs));
                        if (std.mem.eql(u8, lhs_name, "_")) {
                            // Discarding import is allowed
                            break;
                        }
                    }
                    const loc = self.tree.tokenLocation(0, main_token);
                    self.report(loc, .Z028, "");
                    break;
                },
                else => {
                    const loc = self.tree.tokenLocation(0, main_token);
                    self.report(loc, .Z028, "");
                    break;
                },
            }
        }
    }
}

fn hasTopLevelFields(self: *Linter) bool {
    for (self.tree.rootDecls()) |node| {
        const tag = self.tree.nodeTag(node);
        if (tag == .container_field_init or tag == .container_field) {
            return true;
        }
    }
    return false;
}

fn isAtFileLevel(self: *Linter, start_node: Ast.Node.Index) bool {
    var current = start_node;

    while (true) {
        const parent_opt = self.parent_map[@intFromEnum(current)];
        const parent = parent_opt.unwrap() orelse return true; // No parent = root level
        const parent_tag = self.tree.nodeTag(parent);

        // If we hit a container, fn, or test, we're not at file level
        switch (parent_tag) {
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
            .fn_decl,
            .test_decl,
            => return false,
            else => {},
        }

        current = parent;
    }
}

fn isInTestBlock(self: *Linter, start_node: Ast.Node.Index) bool {
    var current = start_node;

    while (true) {
        const parent_opt = self.parent_map[@intFromEnum(current)];
        const parent = parent_opt.unwrap() orelse return false;
        const parent_tag = self.tree.nodeTag(parent);

        if (parent_tag == .test_decl) return true;
        if (parent_tag == .fn_decl) return false; // Functions block test scope

        current = parent;
    }
}

fn findEnclosingStructName(self: *Linter, start_node: Ast.Node.Index) ?[]const u8 {
    var current = start_node;
    var enclosing_container: ?Ast.Node.Index = null;

    // First pass: find the enclosing container
    while (true) {
        const parent_opt = self.parent_map[@intFromEnum(current)];
        const parent = parent_opt.unwrap() orelse break;
        const parent_tag = self.tree.nodeTag(parent);

        const is_container = switch (parent_tag) {
            .container_decl,
            .container_decl_trailing,
            .container_decl_two,
            .container_decl_two_trailing,
            .container_decl_arg,
            .container_decl_arg_trailing,
            => true,
            else => false,
        };

        if (is_container) {
            enclosing_container = parent;
            break;
        }

        current = parent;
    }

    const container = enclosing_container orelse return null;

    // Second pass: check if container is inside a function/test block
    // If so, the struct name isn't accessible from inside, so @This() is valid
    current = container;
    while (true) {
        const parent_opt = self.parent_map[@intFromEnum(current)];
        const parent = parent_opt.unwrap() orelse break;
        const parent_tag = self.tree.nodeTag(parent);

        if (parent_tag == .fn_decl or parent_tag == .test_decl) {
            return null; // Local struct - name not accessible
        }

        current = parent;
    }

    // Container is at module level - check if it's named
    const container_parent_opt = self.parent_map[@intFromEnum(container)];
    const container_parent = container_parent_opt.unwrap() orelse return null;
    const container_parent_tag = self.tree.nodeTag(container_parent);

    return switch (container_parent_tag) {
        .simple_var_decl, .aligned_var_decl, .local_var_decl, .global_var_decl => blk: {
            const var_decl = self.tree.fullVarDecl(container_parent) orelse break :blk null;
            const name_token = var_decl.ast.mut_token + 1;
            break :blk self.tree.tokenSlice(name_token);
        },
        else => null, // Anonymous (returned, passed as arg, etc.)
    };
}

/// Find the enclosing container (struct/union/enum) for a given node
fn findEnclosingContainer(self: *Linter, start_node: Ast.Node.Index) Ast.Node.OptionalIndex {
    var current = start_node;

    while (true) {
        const parent_opt = self.parent_map[@intFromEnum(current)];
        const parent = parent_opt.unwrap() orelse return .none;
        const parent_tag = self.tree.nodeTag(parent);

        const is_container = switch (parent_tag) {
            .container_decl,
            .container_decl_trailing,
            .container_decl_two,
            .container_decl_two_trailing,
            .container_decl_arg,
            .container_decl_arg_trailing,
            => true,
            else => false,
        };

        if (is_container) {
            return parent.toOptional();
        }

        current = parent;
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
                    // ziglint-ignore: Z026
                    self.imported_types.put(self.allocator, name, {}) catch {};
                    continue;
                }

                if (!self.isPublicDecl(node)) continue;
                if (!self.isTypeDecl(var_decl)) continue;

                // ziglint-ignore: Z026
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

fn isPrivateTypeRef(self: *Linter, name: []const u8, enclosing_container: Ast.Node.OptionalIndex) bool {
    if (!isPascalCase(name)) return false;
    if (isBuiltinType(name)) return false;
    if (self.public_types.contains(name)) return false;
    if (self.imported_types.contains(name)) return false;
    // Don't flag Self type (type matching filename for file-as-struct pattern)
    if (self.isSelfType(name)) return false;
    // Check if type is pub within the enclosing container
    if (self.isPublicInContainer(name, enclosing_container)) return false;
    return true;
}

/// Check if a type name is declared as `pub const` within the given container
fn isPublicInContainer(self: *Linter, name: []const u8, container_opt: Ast.Node.OptionalIndex) bool {
    const container = container_opt.unwrap() orelse return false;
    const members = self.getContainerMembers(container) orelse return false;

    for (members) |member| {
        const tag = self.tree.nodeTag(member);
        switch (tag) {
            .simple_var_decl, .aligned_var_decl, .local_var_decl, .global_var_decl => {
                // Check if this is a pub declaration
                if (!self.isPublicDecl(member)) continue;

                // Check if the name matches
                const var_decl = self.tree.fullVarDecl(member) orelse continue;
                const name_token = var_decl.ast.mut_token + 1;
                const decl_name = self.tree.tokenSlice(name_token);
                if (std.mem.eql(u8, decl_name, name)) return true;
            },
            else => {},
        }
    }
    return false;
}

/// Get the member declarations of a container node
fn getContainerMembers(self: *Linter, node: Ast.Node.Index) ?[]const Ast.Node.Index {
    const tag = self.tree.nodeTag(node);
    return switch (tag) {
        .container_decl, .container_decl_trailing => self.tree.containerDecl(node).ast.members,
        .container_decl_two, .container_decl_two_trailing => blk: {
            var buf: [2]Ast.Node.Index = undefined;
            break :blk self.tree.containerDeclTwo(&buf, node).ast.members;
        },
        .container_decl_arg, .container_decl_arg_trailing => self.tree.containerDeclArg(node).ast.members,
        else => null,
    };
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

const ParamKind = enum {
    type_param,
    allocator,
    io,
    comptime_value,
    other,

    fn order(self: ParamKind) u8 {
        return switch (self) {
            .type_param => 0,
            .allocator => 1,
            .io => 2,
            .comptime_value => 3,
            .other => 4,
        };
    }

    fn name(self: ParamKind) []const u8 {
        return switch (self) {
            .type_param => "type",
            .allocator => "Allocator",
            .io => "Io",
            .comptime_value => "comptime",
            .other => "other",
        };
    }
};

fn checkArgumentOrder(self: *Linter, node: Ast.Node.Index) void {
    var buf: [1]Ast.Node.Index = undefined;
    const fn_proto = self.tree.fullFnProto(&buf, node) orelse return;

    var max_order: u8 = 0;
    var max_kind: ParamKind = .type_param;
    var max_token: Ast.TokenIndex = 0;
    var is_first = true;

    var it = fn_proto.iterate(&self.tree);
    while (it.next()) |param| {
        // Skip first param if it's a receiver (type refers to @This() or container type)
        if (is_first) {
            is_first = false;
            if (self.isReceiverParam(param)) continue;
        }

        const kind = self.classifyParam(param);

        const current_order = kind.order();

        if (current_order < max_order) {
            // This parameter is out of order
            const token = param.name_token orelse
                (if (param.type_expr) |te| self.tree.nodeMainToken(te) else continue);
            const loc = self.tree.tokenLocation(0, token);

            const context = std.fmt.allocPrint(self.allocator, "{s}\x00{s}", .{
                kind.name(),
                max_kind.name(),
            }) catch continue;
            // ziglint-ignore: Z026
            self.allocated_contexts.append(self.allocator, context) catch {};
            self.report(loc, .Z023, context);
        }

        if (current_order >= max_order) {
            max_order = current_order;
            max_kind = kind;
            max_token = param.name_token orelse max_token;
        }
    }
}

fn isComptimeParam(self: *Linter, param: Ast.full.FnProto.Param) bool {
    const comptime_token = param.comptime_noalias orelse return false;
    const token_tag = self.tree.tokenTag(comptime_token);
    return token_tag == .keyword_comptime;
}

fn classifyParam(self: *Linter, param: Ast.full.FnProto.Param) ParamKind {
    const type_node = param.type_expr orelse return .other;
    const base_kind = self.classifyTypeNode(type_node);

    // If it's a comptime param that's not a type param, classify as comptime_value
    if (base_kind == .other and self.isComptimeParam(param)) {
        return .comptime_value;
    }

    return base_kind;
}

fn isReceiverParam(self: *Linter, param: Ast.full.FnProto.Param) bool {
    const type_node = param.type_expr orelse return false;

    // Use TypeResolver if available for accurate type resolution
    if (self.type_resolver) |resolver| {
        if (self.module_path) |mod_path| {
            const inner_node = self.unwrapPointerType(type_node);
            const type_info = resolver.typeOf(mod_path, inner_node);
            if (type_info == .user_type) {
                // Check if the type's module matches current module (file-as-struct or local struct)
                if (std.mem.eql(u8, type_info.user_type.module_path, mod_path)) {
                    return true;
                }
            }
        }
    }

    // Fallback: check for @This() or Self
    return self.typeRefersToThis(type_node);
}

fn unwrapPointerType(self: *Linter, node: Ast.Node.Index) Ast.Node.Index {
    const tag = self.tree.nodeTag(node);
    return switch (tag) {
        .ptr_type_aligned, .ptr_type_sentinel, .ptr_type, .ptr_type_bit_range => blk: {
            const ptr_type = self.tree.fullPtrType(node) orelse break :blk node;
            break :blk self.unwrapPointerType(ptr_type.ast.child_type);
        },
        else => node,
    };
}

fn typeRefersToThis(self: *Linter, node: Ast.Node.Index) bool {
    const tag = self.tree.nodeTag(node);
    return switch (tag) {
        .builtin_call_two => blk: {
            const main_token = self.tree.nodeMainToken(node);
            const builtin_name = self.tree.tokenSlice(main_token);
            break :blk std.mem.eql(u8, builtin_name, "@This");
        },
        .ptr_type_aligned, .ptr_type_sentinel, .ptr_type, .ptr_type_bit_range => blk: {
            const ptr_type = self.tree.fullPtrType(node) orelse break :blk false;
            break :blk self.typeRefersToThis(ptr_type.ast.child_type);
        },
        .identifier => blk: {
            const name = self.tree.tokenSlice(self.tree.nodeMainToken(node));
            break :blk std.mem.eql(u8, name, "Self");
        },
        else => false,
    };
}

fn classifyTypeNode(self: *Linter, type_node: Ast.Node.Index) ParamKind {
    // Check for `type` (comptime type parameter)
    if (self.tree.nodeTag(type_node) == .identifier) {
        const type_name = self.tree.tokenSlice(self.tree.nodeMainToken(type_node));
        if (std.mem.eql(u8, type_name, "type")) return .type_param;
    }

    // Use TypeResolver for semantic type resolution (handles aliases)
    if (self.type_resolver) |resolver| {
        if (self.module_path) |mod_path| {
            const type_info = resolver.typeOf(mod_path, type_node);
            if (type_info == .std_type) {
                return self.classifyPath(type_info.std_type.path);
            }
        }
    }

    // Fallback: check for field access chains like std.mem.Allocator or std.Io
    const path = self.getFieldAccessPath(type_node) orelse return .other;
    return self.classifyPath(path);
}

fn classifyPath(self: *Linter, path: []const u8) ParamKind {
    _ = self;
    if (std.mem.eql(u8, path, "std.mem.Allocator") or
        std.mem.eql(u8, path, "mem.Allocator") or
        std.mem.eql(u8, path, "Allocator"))
    {
        return .allocator;
    }

    if (std.mem.eql(u8, path, "std.Io") or
        std.mem.eql(u8, path, "Io"))
    {
        return .io;
    }

    return .other;
}

fn getFieldAccessPath(self: *Linter, node: Ast.Node.Index) ?[]const u8 {
    var parts: [8][]const u8 = undefined;
    var count: usize = 0;

    var current = node;
    while (true) {
        const tag = self.tree.nodeTag(current);
        if (tag == .field_access) {
            const data = self.tree.nodeData(current).node_and_token;
            if (count < parts.len) {
                parts[parts.len - 1 - count] = self.tree.tokenSlice(data[1]);
                count += 1;
            }
            current = data[0];
        } else if (tag == .identifier) {
            if (count < parts.len) {
                parts[parts.len - 1 - count] = self.tree.tokenSlice(self.tree.nodeMainToken(current));
                count += 1;
            }
            break;
        } else {
            return null;
        }
    }

    if (count == 0) return null;

    // Build the path string
    var total_len: usize = 0;
    for (parts[parts.len - count ..]) |p| {
        total_len += p.len + 1;
    }

    const result = self.allocator.alloc(u8, total_len - 1) catch return null;
    var pos: usize = 0;
    for (parts[parts.len - count ..], 0..) |p, i| {
        if (i > 0) {
            result[pos] = '.';
            pos += 1;
        }
        @memcpy(result[pos..][0..p.len], p);
        pos += p.len;
    }

    // ziglint-ignore: Z026
    self.allocated_contexts.append(self.allocator, result) catch {};
    return result;
}

fn checkExposedPrivateType(self: *Linter, node: Ast.Node.Index) void {
    var buf: [1]Ast.Node.Index = undefined;
    const fn_proto = self.tree.fullFnProto(&buf, node) orelse return;

    if (!self.isPublicDecl(node)) return;

    // Find enclosing container (struct/union/enum) if any
    const enclosing_container = self.findEnclosingContainer(node);

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
        self.checkTypeNodeForPrivateWithGenerics(ret_node, fn_proto, generic_params[0..generic_count], enclosing_container);
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
        self.checkTypeNodeForPrivateWithGenerics(type_node, fn_proto, generic_params[0..generic_count], enclosing_container);
    }
}

fn checkTypeNodeForPrivateWithGenerics(
    self: *Linter,
    type_node: Ast.Node.Index,
    fn_proto: Ast.full.FnProto,
    generic_params: []const []const u8,
    enclosing_container: Ast.Node.OptionalIndex,
) void {
    self.checkTypeNodeForPrivateImpl(type_node, fn_proto, generic_params, false, enclosing_container);
}

fn checkTypeNodeForPrivateImpl(
    self: *Linter,
    type_node: Ast.Node.Index,
    fn_proto: Ast.full.FnProto,
    generic_params: []const []const u8,
    is_error_position: bool,
    enclosing_container: Ast.Node.OptionalIndex,
) void {
    const tag = self.tree.nodeTag(type_node);

    switch (tag) {
        .identifier => {
            const type_name = self.tree.tokenSlice(self.tree.nodeMainToken(type_node));
            // Skip generic type parameters
            for (generic_params) |gp| {
                if (std.mem.eql(u8, type_name, gp)) return;
            }
            if (self.isPrivateTypeRef(type_name, enclosing_container)) {
                self.reportPrivateType(fn_proto, type_name, is_error_position);
            }
        },
        .optional_type => {
            const child = self.tree.nodeData(type_node).node;
            self.checkTypeNodeForPrivateImpl(child, fn_proto, generic_params, is_error_position, enclosing_container);
        },
        .error_union => {
            const data = self.tree.nodeData(type_node).node_and_node;
            self.checkTypeNodeForPrivateImpl(data[0], fn_proto, generic_params, true, enclosing_container);
            self.checkTypeNodeForPrivateImpl(data[1], fn_proto, generic_params, false, enclosing_container);
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
        .simple_var_decl, .aligned_var_decl, .local_var_decl, .global_var_decl => {
            self.checkVarDecl(node);
        },
        .@"return" => self.checkReturn(node),
        .call_one, .call_one_comma, .call, .call_comma => {
            self.checkCallArgs(node);
            self.checkRedundantAsInCallArgs(node);
            self.checkDeprecatedCall(node);
            self.checkCompoundAssert(node);
        },
        .array_init_one,
        .array_init_one_comma,
        .array_init_dot_two,
        .array_init_dot_two_comma,
        .array_init_dot,
        .array_init_dot_comma,
        .array_init,
        .array_init_comma,
        => {
            self.checkRedundantAsInArrayInit(node);
        },
        .struct_init_one,
        .struct_init_one_comma,
        .struct_init_dot_two,
        .struct_init_dot_two_comma,
        .struct_init_dot,
        .struct_init_dot_comma,
        .struct_init,
        .struct_init_comma,
        => {
            self.checkRedundantAsInStructInit(node);
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
            // Track the function's return type for checks inside the body
            var buf: [1]Ast.Node.Index = undefined;
            const fn_proto = self.tree.fullFnProto(&buf, node);
            const prev_return_type = self.current_fn_return_type;
            if (fn_proto) |proto| {
                self.current_fn_return_type = proto.ast.return_type;
            }
            self.visitNode(data[0]);
            self.visitNode(data[1]);
            self.current_fn_return_type = prev_return_type;
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
        // Assignments - visit both sides to catch calls in RHS like `_ = deprecatedFunc()`
        .assign => {
            const data = self.tree.nodeData(node).node_and_node;
            self.visitNode(data[0]);
            self.visitNode(data[1]);
        },
        // Variable declarations - visit both type annotation and init node
        .simple_var_decl, .aligned_var_decl, .local_var_decl, .global_var_decl => {
            const var_decl = self.tree.fullVarDecl(node) orelse return;
            // Visit type annotation (e.g., for `var x: std.ArrayListUnmanaged(u8)` to catch deprecated calls)
            if (var_decl.ast.type_node.unwrap()) |type_node| self.visitNode(type_node);
            if (var_decl.ast.init_node.unwrap()) |init_node| self.visitNode(init_node);
        },
        // Container declarations (structs, enums, unions) - visit members
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
        => {
            var buf: [2]Ast.Node.Index = undefined;
            const container = self.tree.fullContainerDecl(&buf, node) orelse return;
            for (container.ast.members) |member| {
                self.visitNode(member);
            }
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

    // Check for underscore prefix
    if (self.config.isRuleEnabled(.Z031) and hasUnderscorePrefix(name)) {
        const loc = self.tree.tokenLocation(0, name_token);
        self.report(loc, .Z031, name);
    }

    // Check for acronym casing
    // Check for acronym casing
    if (self.config.isRuleEnabled(.Z032)) {
        if (checkAcronymCasing(self.allocator, name)) |suggestion| {
            const context = self.allocator.alloc(u8, name.len + 1 + suggestion.len) catch {
                self.allocator.free(suggestion);
                return;
            };
            @memcpy(context[0..name.len], name);
            context[name.len] = 0;
            @memcpy(context[name.len + 1 ..], suggestion);
            // ziglint-ignore: Z026
            self.allocated_contexts.append(self.allocator, context) catch {};
            // ziglint-ignore: Z026
            self.allocated_contexts.append(self.allocator, suggestion) catch {};
            const loc = self.tree.tokenLocation(0, name_token);
            self.report(loc, .Z032, context);
        }
    }

    // Check for redundant words (disabled by default)
    if (self.config.isRuleEnabled(.Z033)) {
        if (findRedundantWord(name)) |word| {
            const context = self.allocator.alloc(u8, name.len + 1 + word.len) catch return;
            @memcpy(context[0..name.len], name);
            context[name.len] = 0;
            @memcpy(context[name.len + 1 ..], word);
            // ziglint-ignore: Z026
            self.allocated_contexts.append(self.allocator, context) catch {};
            const loc = self.tree.tokenLocation(0, name_token);
            self.report(loc, .Z033, context);
        }
    }

    self.checkExposedPrivateType(node);
    self.checkArgumentOrder(node);
    self.checkDeinitUndefined(node, fn_proto);
}

fn checkDeinitUndefined(self: *Linter, node: Ast.Node.Index, fn_proto: Ast.full.FnProto) void {
    if (!self.config.isRuleEnabled(.Z030)) return;

    // Only check functions named "deinit"
    const name_token = fn_proto.name_token orelse return;
    const name = self.tree.tokenSlice(name_token);
    if (!std.mem.eql(u8, name, "deinit")) return;

    // Check if first parameter is a pointer type
    var param_it = fn_proto.iterate(&self.tree);
    const first_param = param_it.next() orelse return;
    const param_type = first_param.type_expr orelse return;
    if (!self.isPointerType(param_type)) return;

    // Get the parameter name (usually "self")
    const param_name = if (first_param.name_token) |t| self.tree.tokenSlice(t) else return;

    // Get function body
    const body_node = self.tree.nodeData(node).node_and_node[1];

    // Check for `defer self.* = undefined;` anywhere in body - this handles all paths
    if (self.hasDeferSelfUndefined(body_node, param_name)) return;

    // Check for early returns (which would skip final self.* = undefined)
    if (self.hasEarlyReturn(body_node)) {
        const loc = self.tree.tokenLocation(0, name_token);
        self.report(loc, .Z030, "has early return without defer");
        return;
    }

    // Check if last statement is `self.* = undefined;`
    if (self.lastStatementIsSelfUndefined(body_node, param_name)) return;

    // None of the valid patterns found
    const loc = self.tree.tokenLocation(0, name_token);
    self.report(loc, .Z030, "");
}

fn isPointerType(self: *Linter, node: Ast.Node.Index) bool {
    const tag = self.tree.nodeTag(node);
    return switch (tag) {
        .ptr_type_aligned, .ptr_type_sentinel, .ptr_type, .ptr_type_bit_range => true,
        else => false,
    };
}

fn hasDeferSelfUndefined(self: *Linter, body_node: Ast.Node.Index, param_name: []const u8) bool {
    // Iterate through all nodes looking for defer
    var buf: [2]Ast.Node.Index = undefined;
    const stmts = self.tree.blockStatements(&buf, body_node) orelse return false;

    for (stmts) |stmt| {
        if (self.tree.nodeTag(stmt) == .@"defer") {
            const defer_expr = self.tree.nodeData(stmt).node;
            if (self.isSelfUndefinedAssign(defer_expr, param_name)) return true;
        }
    }
    return false;
}

fn hasEarlyReturn(self: *Linter, body_node: Ast.Node.Index) bool {
    var buf: [2]Ast.Node.Index = undefined;
    const stmts = self.tree.blockStatements(&buf, body_node) orelse return false;

    // Check all statements except the last one for returns
    if (stmts.len <= 1) return false;

    for (stmts[0 .. stmts.len - 1]) |stmt| {
        if (self.containsReturn(stmt)) return true;
    }
    return false;
}

fn containsReturn(self: *Linter, node: Ast.Node.Index) bool {
    const tag = self.tree.nodeTag(node);
    if (tag == .@"return") return true;

    // Recursively check children for returns (e.g., in if blocks)
    switch (tag) {
        .@"if", .if_simple => {
            const full_if = self.tree.fullIf(node) orelse return false;
            if (self.containsReturn(full_if.ast.then_expr)) return true;
            if (full_if.ast.else_expr.unwrap()) |else_node| {
                if (self.containsReturn(else_node)) return true;
            }
        },
        .block, .block_semicolon, .block_two, .block_two_semicolon => {
            var block_buf: [2]Ast.Node.Index = undefined;
            const block_stmts = self.tree.blockStatements(&block_buf, node) orelse return false;
            for (block_stmts) |stmt| {
                if (self.containsReturn(stmt)) return true;
            }
        },
        else => {},
    }
    return false;
}

fn lastStatementIsSelfUndefined(self: *Linter, body_node: Ast.Node.Index, param_name: []const u8) bool {
    var buf: [2]Ast.Node.Index = undefined;
    const stmts = self.tree.blockStatements(&buf, body_node) orelse return false;
    if (stmts.len == 0) return false;

    const last_stmt = stmts[stmts.len - 1];
    return self.isSelfUndefinedAssign(last_stmt, param_name);
}

fn isSelfUndefinedAssign(self: *Linter, node: Ast.Node.Index, param_name: []const u8) bool {
    if (self.tree.nodeTag(node) != .assign) return false;

    const assign_data = self.tree.nodeData(node).node_and_node;
    const lhs = assign_data[0];
    const rhs = assign_data[1];

    // LHS must be deref (self.*)
    if (self.tree.nodeTag(lhs) != .deref) return false;

    // The dereferenced expression must be the parameter name
    const deref_inner = self.tree.nodeData(lhs).node;
    if (self.tree.nodeTag(deref_inner) != .identifier) return false;
    const deref_name = self.tree.tokenSlice(self.tree.nodeMainToken(deref_inner));
    if (!std.mem.eql(u8, deref_name, param_name)) return false;

    // RHS must be undefined
    if (self.tree.nodeTag(rhs) != .identifier) return false;
    const rhs_name = self.tree.tokenSlice(self.tree.nodeMainToken(rhs));
    return std.mem.eql(u8, rhs_name, "undefined");
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

    if (!isSnakeCase(name) and !isTypeAlias(self, var_decl) and !isFunctionAlias(self, var_decl)) {
        const loc = self.tree.tokenLocation(0, name_token);
        self.report(loc, .Z006, name);
    }

    // Check for underscore prefix
    if (self.config.isRuleEnabled(.Z031) and hasUnderscorePrefix(name)) {
        const loc = self.tree.tokenLocation(0, name_token);
        self.report(loc, .Z031, name);
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

    // Check for acronym casing (for type aliases)
    if (self.config.isRuleEnabled(.Z032) and isTypeAlias(self, var_decl)) {
        if (checkAcronymCasing(self.allocator, name)) |suggestion| {
            const context = self.allocator.alloc(u8, name.len + 1 + suggestion.len) catch {
                self.allocator.free(suggestion);
                return;
            };
            @memcpy(context[0..name.len], name);
            context[name.len] = 0;
            @memcpy(context[name.len + 1 ..], suggestion);
            // ziglint-ignore: Z026
            self.allocated_contexts.append(self.allocator, context) catch {};
            // ziglint-ignore: Z026
            self.allocated_contexts.append(self.allocator, suggestion) catch {};
            const loc = self.tree.tokenLocation(0, name_token);
            self.report(loc, .Z032, context);
        }
    }

    // Check for redundant words (disabled by default)
    if (self.config.isRuleEnabled(.Z033) and isTypeAlias(self, var_decl)) {
        if (findRedundantWord(name)) |word| {
            const context = self.allocator.alloc(u8, name.len + 1 + word.len) catch return;
            @memcpy(context[0..name.len], name);
            context[name.len] = 0;
            @memcpy(context[name.len + 1 ..], word);
            // ziglint-ignore: Z026
            self.allocated_contexts.append(self.allocator, context) catch {};
            const loc = self.tree.tokenLocation(0, name_token);
            self.report(loc, .Z033, context);
        }
    }

    self.checkDupeImport(var_decl, name_token);
    self.trackImportBinding(node, var_decl, name_token);
    self.checkRedundantAsInVarDecl(var_decl);
}

fn checkRedundantAsInVarDecl(self: *Linter, var_decl: Ast.full.VarDecl) void {
    // Need both a type annotation and an init expression
    const type_node = var_decl.ast.type_node.unwrap() orelse return;
    const init_node = var_decl.ast.init_node.unwrap() orelse return;

    // Get the declared type name
    const decl_type_name = self.getTypeNodeName(type_node) orelse return;

    // Get the @as type from init expression
    const as_type_name = self.getAsTypeName(init_node) orelse return;

    // Compare types
    if (std.mem.eql(u8, decl_type_name, as_type_name)) {
        const loc = self.tree.tokenLocation(0, self.tree.nodeMainToken(init_node));
        self.report(loc, .Z018, as_type_name);
    }
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
        // ziglint-ignore: Z026
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
        // ziglint-ignore: Z026
        self.seen_imports.put(self.allocator, import_path, name_token) catch {};
    }
}

fn checkReturn(self: *Linter, node: Ast.Node.Index) void {
    const return_expr = self.tree.nodeData(node).opt_node.unwrap() orelse return;
    self.checkRedundantType(return_expr, true);
    self.checkReturnTry(node, return_expr);
    self.checkRedundantAsInReturn(node, return_expr);
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

fn checkCatchReturnAll(self: *Linter) void {
    for (0..self.tree.nodes.len) |i| {
        const node: Ast.Node.Index = @enumFromInt(i);
        if (self.tree.nodeTag(node) != .@"catch") continue;

        const data = self.tree.nodeData(node).node_and_node;
        const rhs = data[1];

        if (self.tree.nodeTag(rhs) != .@"return") continue;

        // Must have a capture payload: `catch |err|`
        const catch_token = self.tree.nodeMainToken(node);
        const pipe_token = catch_token + 1;
        if (self.tree.tokenTag(pipe_token) != .pipe) continue;

        const payload_token = pipe_token + 1;
        const payload_name = self.tree.tokenSlice(payload_token);

        // The return expression must be an identifier matching the payload
        const return_expr = self.tree.nodeData(rhs).opt_node.unwrap() orelse continue;
        if (self.tree.nodeTag(return_expr) != .identifier) continue;
        const return_name = self.tree.tokenSlice(self.tree.nodeMainToken(return_expr));

        if (!std.mem.eql(u8, payload_name, return_name)) continue;

        const loc = self.tree.tokenLocation(0, catch_token);
        self.report(loc, .Z025, payload_name);
    }
}

fn checkEmptyCatchAll(self: *Linter) void {
    for (0..self.tree.nodes.len) |i| {
        const node: Ast.Node.Index = @enumFromInt(i);
        if (self.tree.nodeTag(node) != .@"catch") continue;

        const data = self.tree.nodeData(node).node_and_node;
        const rhs = data[1];

        if (!self.isEmptyBlock(rhs)) continue;

        // Skip if under a defer node
        if (self.isUnderDefer(node)) continue;

        const catch_token = self.tree.nodeMainToken(node);
        const loc = self.tree.tokenLocation(0, catch_token);
        self.report(loc, .Z026, "");
    }
}

fn checkInstanceDeclAccess(self: *Linter) void {
    const resolver = self.type_resolver orelse return;
    const mod_path = self.module_path orelse return;

    for (0..self.tree.nodes.len) |i| {
        const node: Ast.Node.Index = @enumFromInt(i);
        if (self.tree.nodeTag(node) != .field_access) continue;

        const data = self.tree.nodeData(node).node_and_token;
        const lhs_node = data[0];
        const field_token = data[1];
        const field_name = self.tree.tokenSlice(field_token);

        if (resolver.isTypeRef(mod_path, lhs_node)) continue;

        const lhs_type = resolver.typeOf(mod_path, lhs_node);
        if (!resolver.isContainerLevelDecl(lhs_type, field_name)) continue;

        const type_name = switch (lhs_type) {
            .user_type => |u| u.name,
            else => continue,
        };

        const loc = self.tree.tokenLocation(0, field_token);
        const context = std.fmt.allocPrint(self.allocator, "{s}\x00{s}", .{
            field_name, type_name,
        }) catch continue;
        // ziglint-ignore: Z026
        self.allocated_contexts.append(self.allocator, context) catch {};
        self.report(loc, .Z027, context);
    }
}

fn isEmptyBlock(self: *Linter, node: Ast.Node.Index) bool {
    const tag = self.tree.nodeTag(node);
    return switch (tag) {
        .block_two, .block_two_semicolon => {
            const block_data = self.tree.nodeData(node).opt_node_and_opt_node;
            return block_data[0] == .none and block_data[1] == .none;
        },
        .block, .block_semicolon => {
            var buf: [2]Ast.Node.Index = undefined;
            const stmts = self.tree.blockStatements(&buf, node) orelse return true;
            return stmts.len == 0;
        },
        else => false,
    };
}

fn isUnderDefer(self: *Linter, node: Ast.Node.Index) bool {
    if (self.parent_map.len == 0) return false;
    var current = node;
    while (true) {
        const parent_opt = self.parent_map[@intFromEnum(current)];
        const parent = parent_opt.unwrap() orelse return false;
        const tag = self.tree.nodeTag(parent);
        if (tag == .@"defer" or tag == .@"errdefer") return true;
        current = parent;
    }
}

fn checkRedundantAsInReturn(self: *Linter, return_node: Ast.Node.Index, return_expr: Ast.Node.Index) void {
    // Get the @as type from return expression
    const as_type_name = self.getAsTypeName(return_expr) orelse return;

    // Get function's return type
    const fn_return_type = self.current_fn_return_type.unwrap() orelse return;
    const fn_return_name = self.getTypeNodeName(fn_return_type) orelse return;

    // Compare types
    if (std.mem.eql(u8, as_type_name, fn_return_name)) {
        const loc = self.tree.tokenLocation(0, self.tree.nodeMainToken(return_node));
        self.report(loc, .Z018, as_type_name);
    }
}

fn getAsTypeName(self: *Linter, node: Ast.Node.Index) ?[]const u8 {
    const tag = self.tree.nodeTag(node);
    if (tag != .builtin_call_two and tag != .builtin_call_two_comma and
        tag != .builtin_call and tag != .builtin_call_comma) return null;

    const main_token = self.tree.nodeMainToken(node);
    const builtin_name = self.tree.tokenSlice(main_token);
    if (!std.mem.eql(u8, builtin_name, "@as")) return null;

    var buf: [2]Ast.Node.Index = undefined;
    const params = self.tree.builtinCallParams(&buf, node) orelse return null;
    if (params.len < 1) return null;

    return self.getTypeNodeName(params[0]);
}

fn getTypeNodeName(self: *Linter, type_node: Ast.Node.Index) ?[]const u8 {
    const tag = self.tree.nodeTag(type_node);
    return switch (tag) {
        .identifier => self.tree.tokenSlice(self.tree.nodeMainToken(type_node)),
        else => null,
    };
}

fn checkRedundantAsInCallArgs(self: *Linter, node: Ast.Node.Index) void {
    var call_buf: [1]Ast.Node.Index = undefined;
    const call = self.tree.fullCall(&call_buf, node) orelse return;
    const params = call.ast.params;
    if (params.len == 0) return;

    // Resolve the called function's prototype and determine param offset
    const resolved = self.resolveCalledFnProto(call.ast.fn_expr) orelse return;
    const fn_tree = resolved.tree;
    var fn_buf: [1]Ast.Node.Index = undefined;
    const fn_proto = fn_tree.fullFnProto(&fn_buf, resolved.fn_node) orelse return;

    // For method calls (field_access), skip the receiver param
    const skip_receiver = self.tree.nodeTag(call.ast.fn_expr) == .field_access;

    var it = fn_proto.iterate(fn_tree);
    var param_idx: usize = 0;

    if (skip_receiver) {
        _ = it.next();
    }

    while (it.next()) |param| : (param_idx += 1) {
        if (param_idx >= params.len) break;
        const arg = params[param_idx];

        const as_type_name = self.getAsTypeName(arg) orelse continue;
        const type_node = param.type_expr orelse continue;
        const param_type_name = self.getTypeNodeNameFromTree(fn_tree, type_node) orelse continue;

        if (std.mem.eql(u8, as_type_name, param_type_name)) {
            const loc = self.tree.tokenLocation(0, self.tree.nodeMainToken(arg));
            self.report(loc, .Z029, as_type_name);
        }
    }
}

const ResolvedFnProto = struct {
    tree: *const Ast,
    fn_node: Ast.Node.Index,
};

fn resolveCalledFnProto(self: *Linter, callee_expr: Ast.Node.Index) ?ResolvedFnProto {
    const tag = self.tree.nodeTag(callee_expr);
    switch (tag) {
        .identifier => {
            const fn_name = self.tree.tokenSlice(self.tree.nodeMainToken(callee_expr));
            for (self.tree.rootDecls()) |decl_node| {
                if (self.tree.nodeTag(decl_node) != .fn_decl) continue;
                var buf: [1]Ast.Node.Index = undefined;
                const fn_proto = self.tree.fullFnProto(&buf, decl_node) orelse continue;
                const name_token = fn_proto.name_token orelse continue;
                if (std.mem.eql(u8, self.tree.tokenSlice(name_token), fn_name)) {
                    return .{ .tree = &self.tree, .fn_node = decl_node };
                }
            }
        },
        .field_access => {
            const resolver = self.type_resolver orelse return null;
            const mod_path = self.module_path orelse return null;
            const data = self.tree.nodeData(callee_expr).node_and_token;
            const receiver_node = data[0];
            const method_name = self.tree.tokenSlice(data[1]);
            const receiver_type = resolver.typeOf(mod_path, receiver_node);
            const method_def = resolver.findMethodDef(receiver_type, method_name) orelse return null;
            const mod = resolver.graph.getModule(method_def.module_path) orelse return null;
            return .{ .tree = &mod.tree, .fn_node = method_def.node };
        },
        else => {},
    }
    return null;
}

fn checkRedundantAsInArrayInit(self: *Linter, node: Ast.Node.Index) void {
    var buf: [2]Ast.Node.Index = undefined;
    const array_init = self.tree.fullArrayInit(&buf, node) orelse return;
    const type_expr = array_init.ast.type_expr.unwrap() orelse return;

    // Get the element type from the array type expression
    const elem_type_name = self.getArrayElemTypeName(type_expr) orelse return;

    for (array_init.ast.elements) |elem| {
        const as_type_name = self.getAsTypeName(elem) orelse continue;
        if (std.mem.eql(u8, as_type_name, elem_type_name)) {
            const loc = self.tree.tokenLocation(0, self.tree.nodeMainToken(elem));
            self.report(loc, .Z029, as_type_name);
        }
    }
}

fn getArrayElemTypeName(self: *Linter, type_expr: Ast.Node.Index) ?[]const u8 {
    const type_tag = self.tree.nodeTag(type_expr);
    return switch (type_tag) {
        .array_type, .array_type_sentinel => {
            const array_type = self.tree.fullArrayType(type_expr) orelse return null;
            return self.getTypeNodeName(array_type.ast.elem_type);
        },
        else => null,
    };
}

fn getTypeNodeNameFromTree(_: *Linter, tree: *const Ast, type_node: Ast.Node.Index) ?[]const u8 {
    const tag = tree.nodeTag(type_node);
    return switch (tag) {
        .identifier => tree.tokenSlice(tree.nodeMainToken(type_node)),
        else => null,
    };
}

fn checkRedundantAsInStructInit(self: *Linter, node: Ast.Node.Index) void {
    var buf: [2]Ast.Node.Index = undefined;
    const struct_init = self.tree.fullStructInit(&buf, node) orelse return;
    if (struct_init.ast.fields.len == 0) return;

    // Determine the struct type name
    const struct_type_name = self.resolveStructInitTypeName(node, struct_init) orelse return;

    for (struct_init.ast.fields) |field_value| {
        const as_type_name = self.getAsTypeName(field_value) orelse continue;

        // Get field name: token before '=' before the value expression
        const value_main_token = self.tree.nodeMainToken(field_value);
        if (value_main_token < 2) continue;
        const field_name_token = value_main_token - 2;
        if (self.tree.tokenTag(field_name_token) != .identifier) continue;
        const field_name = self.tree.tokenSlice(field_name_token);

        const field_type_name = self.findContainerFieldType(struct_type_name, field_name) orelse continue;
        if (std.mem.eql(u8, as_type_name, field_type_name)) {
            const loc = self.tree.tokenLocation(0, self.tree.nodeMainToken(field_value));
            self.report(loc, .Z029, as_type_name);
        }
    }
}

fn resolveStructInitTypeName(self: *Linter, node: Ast.Node.Index, struct_init: Ast.full.StructInit) ?[]const u8 {
    // Case 1: explicit type expression (e.g., Foo{ .x = 1 })
    if (struct_init.ast.type_expr.unwrap()) |type_expr| {
        return self.getTypeNodeName(type_expr);
    }

    // Case 2: anonymous init — walk parent_map to find type context
    if (self.parent_map.len == 0) return null;
    const parent = self.parent_map[@intFromEnum(node)].unwrap() orelse return null;
    const parent_tag = self.tree.nodeTag(parent);
    switch (parent_tag) {
        .simple_var_decl, .aligned_var_decl, .local_var_decl, .global_var_decl => {
            const var_decl = self.tree.fullVarDecl(parent) orelse return null;
            const type_node = var_decl.ast.type_node.unwrap() orelse return null;
            return self.getTypeNodeName(type_node);
        },
        else => return null,
    }
}

fn findContainerFieldType(self: *Linter, struct_type_name: []const u8, field_name: []const u8) ?[]const u8 {
    return self.findContainerFieldTypeInTree(&self.tree, struct_type_name, field_name);
}

fn findContainerFieldTypeInTree(self: *Linter, tree: *const Ast, struct_type_name: []const u8, field_name: []const u8) ?[]const u8 {
    _ = self;
    for (tree.rootDecls()) |decl_node| {
        const tag = tree.nodeTag(decl_node);
        switch (tag) {
            .simple_var_decl, .aligned_var_decl, .local_var_decl, .global_var_decl => {
                const var_decl = tree.fullVarDecl(decl_node) orelse continue;
                const name_token = var_decl.ast.mut_token + 1;
                if (!std.mem.eql(u8, tree.tokenSlice(name_token), struct_type_name)) continue;
                const init_node = var_decl.ast.init_node.unwrap() orelse continue;

                var container_buf: [2]Ast.Node.Index = undefined;
                const container = tree.fullContainerDecl(&container_buf, init_node) orelse continue;
                for (container.ast.members) |member| {
                    const field = tree.fullContainerField(member) orelse continue;
                    if (!std.mem.eql(u8, tree.tokenSlice(field.ast.main_token), field_name)) continue;
                    const type_node = field.ast.type_expr.unwrap() orelse return null;
                    const field_type_tag = tree.nodeTag(type_node);
                    return switch (field_type_tag) {
                        .identifier => tree.tokenSlice(tree.nodeMainToken(type_node)),
                        else => null,
                    };
                }
            },
            else => {},
        }
    }
    return null;
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
    const fn_expr_tag = self.tree.nodeTag(fn_expr);

    var method_def: ?TypeResolver.MethodDef = null;
    var stdlib_decl: ?TypeResolver.MethodDef = null;
    var name_token: Ast.TokenIndex = undefined;
    var fn_name: []const u8 = undefined;

    if (fn_expr_tag == .field_access) {
        const data = self.tree.nodeData(fn_expr).node_and_token;
        const receiver_node = data[0];
        name_token = data[1];
        fn_name = self.tree.tokenSlice(name_token);

        const receiver_type = resolver.typeOf(mod_path, receiver_node);
        method_def = resolver.findMethodDef(receiver_type, fn_name);

        // For stdlib types, also get the declaration without following aliases
        // (the alias itself may be deprecated, like std.ArrayListUnmanaged)
        if (receiver_type == .std_type) {
            stdlib_decl = resolver.findStdlibDecl(receiver_type.std_type.path, fn_name);
        }
    } else if (fn_expr_tag == .identifier) {
        // Direct function call in the same module (e.g., `DeprecatedFunc()`)
        name_token = self.tree.nodeMainToken(fn_expr);
        fn_name = self.tree.tokenSlice(name_token);

        // Look up the function in the current module
        method_def = resolver.findFnInCurrentModule(mod_path, fn_name);
    } else {
        return;
    }

    // Check the target definition for deprecation
    if (method_def) |def| {
        if (self.checkDefDeprecation(def, name_token, fn_name)) return;
    }

    // Also check the stdlib declaration itself (for deprecated aliases like std.ArrayListUnmanaged)
    if (stdlib_decl) |decl| {
        _ = self.checkDefDeprecation(decl, name_token, fn_name);
    }
}

fn checkDefDeprecation(self: *Linter, def: TypeResolver.MethodDef, name_token: Ast.TokenIndex, fn_name: []const u8) bool {
    const resolver = self.type_resolver orelse return false;
    const mod = resolver.graph.getModule(def.module_path) orelse return false;

    // Check cache first
    const cache_key = DeprecationKey.init(def.module_path, def.node);
    if (self.deprecation_cache.get(cache_key)) |is_deprecated| {
        if (!is_deprecated) return false;

        // Still deprecated, extract doc comment for the error message
        const doc = doc_comments.getDocComment(self.allocator, &mod.tree, def.node) orelse return false;
        defer self.allocator.free(doc);

        const loc = self.tree.tokenLocation(0, name_token);
        const msg = std.fmt.allocPrint(self.allocator, "'{s}' is deprecated: {s}", .{ fn_name, doc }) catch return false;
        self.allocated_contexts.append(self.allocator, msg) catch {
            self.allocator.free(msg);
            return false;
        };
        self.report(loc, .Z011, msg);
        return true;
    }

    // Not in cache, extract doc comment and cache the result
    const doc = doc_comments.getDocComment(self.allocator, &mod.tree, def.node) orelse {
        // No doc comment, cache as not deprecated (cache failure is non-critical)
        self.deprecation_cache.put(self.allocator, cache_key, false) catch return false;
        return false;
    };
    defer self.allocator.free(doc);

    const is_deprecated = containsDeprecated(doc);

    if (is_deprecated) {
        // Cache before reporting (cache failure is non-critical)
        self.deprecation_cache.put(self.allocator, cache_key, true) catch return true;

        const loc = self.tree.tokenLocation(0, name_token);
        const msg = std.fmt.allocPrint(self.allocator, "'{s}' is deprecated: {s}", .{ fn_name, doc }) catch return false;
        self.allocated_contexts.append(self.allocator, msg) catch {
            self.allocator.free(msg);
            return false;
        };
        self.report(loc, .Z011, msg);
        return true;
    }

    // Not deprecated, cache the result (cache failure is non-critical)
    self.deprecation_cache.put(self.allocator, cache_key, false) catch return false;
    return false;
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
    // Must start with lowercase letter
    if (name[0] >= 'A' and name[0] <= 'Z') return false;
    // Leading underscore is allowed (private/internal convention)
    if (name[0] == '_') return true;

    // No underscores allowed in camelCase (except leading)
    for (name) |c| {
        if (c == '_') return false;
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

/// Returns true if the identifier has an underscore prefix (but not just `_` or `__`).
fn hasUnderscorePrefix(name: []const u8) bool {
    if (name.len < 2) return false;
    if (name[0] != '_') return false;
    // Allow `__` double-underscore prefix (e.g., `__builtin`)
    if (name[1] == '_') return false;
    return true;
}

/// Checks if a name has incorrect acronym casing (e.g., XMLParser instead of XmlParser).
/// Returns the suggested fix if there's an issue, null otherwise.
fn checkAcronymCasing(allocator: std.mem.Allocator, name: []const u8) ?[]const u8 {
    if (name.len < 2) return null;

    // Find sequences of 2+ uppercase letters that should be title-cased
    // XMLParser -> XmlParser (XML at start)
    // readXML -> readXml (XML at end)
    // HTTPSConnection -> HttpsConnection (HTTPS at start)
    // getHTTPSConnection -> getHttpsConnection (HTTPS in middle)

    var result = allocator.alloc(u8, name.len) catch return null;
    @memcpy(result, name);
    var has_issue = false;

    var i: usize = 0;
    while (i < name.len) {
        if (isUppercase(name[i])) {
            // Found start of potential acronym
            const start = i;
            var end = i + 1;
            while (end < name.len and isUppercase(name[end])) {
                end += 1;
            }

            const acronym_len = end - start;
            if (acronym_len >= 2) {
                // We have 2+ consecutive uppercase letters
                // Check if this is at the end or followed by lowercase
                if (end < name.len and isLowercase(name[end])) {
                    // e.g., "XMLParser" - the last letter of "XML" is part of "Parser"
                    // Convert all but last uppercase to lowercase: "XmlParser"
                    for (start + 1..end - 1) |j| {
                        result[j] = toLowercase(name[j]);
                    }
                    if (acronym_len > 2) has_issue = true;
                } else {
                    // At end or followed by non-alpha (e.g., "readXML" or "XML123")
                    // Convert all but first to lowercase: "readXml" or "Xml123"
                    for (start + 1..end) |j| {
                        result[j] = toLowercase(name[j]);
                    }
                    if (acronym_len >= 2) has_issue = true;
                }
            }
            i = end;
        } else {
            i += 1;
        }
    }

    if (has_issue) {
        return result;
    } else {
        allocator.free(result);
        return null;
    }
}

fn isUppercase(c: u8) bool {
    return c >= 'A' and c <= 'Z';
}

fn isLowercase(c: u8) bool {
    return c >= 'a' and c <= 'z';
}

fn toLowercase(c: u8) u8 {
    if (c >= 'A' and c <= 'Z') return c + 32;
    return c;
}

/// Words that are considered redundant in identifier names per the Zig style guide.
const redundant_words = [_][]const u8{
    "Value",
    "Data",
    "Context",
    "Manager",
    "State",
    "utils",
    "misc",
    "Util",
    "Utils",
    "Misc",
};

/// Checks if a name contains a redundant word and returns it if found.
fn findRedundantWord(name: []const u8) ?[]const u8 {
    // Check if the name contains any redundant word as a complete word boundary
    for (redundant_words) |word| {
        if (containsWordBoundary(name, word)) {
            return word;
        }
    }
    return null;
}

/// Returns true if name contains word at a word boundary (start, end, or camelCase boundary).
fn containsWordBoundary(name: []const u8, word: []const u8) bool {
    if (word.len > name.len) return false;

    // Check if name equals word exactly
    if (std.mem.eql(u8, name, word)) return true;

    // Check if name starts with word followed by uppercase or end
    if (std.mem.startsWith(u8, name, word)) {
        if (word.len == name.len) return true;
        const next = name[word.len];
        // Word boundary: followed by uppercase (camelCase) or non-alpha
        if (isUppercase(next) or (!isLowercase(next) and !isUppercase(next))) return true;
    }

    // Check if name ends with word preceded by lowercase
    if (std.mem.endsWith(u8, name, word) and name.len > word.len) {
        const prev = name[name.len - word.len - 1];
        if (isLowercase(prev)) return true;
    }

    // Check for word in middle with camelCase boundaries
    var i: usize = 1;
    while (i + word.len <= name.len) {
        if (std.mem.startsWith(u8, name[i..], word)) {
            const prev = name[i - 1];
            // Must be preceded by lowercase (camelCase boundary)
            if (isLowercase(prev)) {
                if (i + word.len == name.len) return true;
                const next = name[i + word.len];
                // Must be followed by uppercase or non-alpha
                if (isUppercase(next) or (!isLowercase(next) and !isUppercase(next))) return true;
            }
        }
        i += 1;
    }

    return false;
}

/// Returns true if the identifier is a primitive type (e.g., i32, u8, f64, bool, etc.)
fn isPrimitiveType(name: []const u8) bool {
    const primitives = [_][]const u8{
        "bool",     "true",         "false",          "null",        "undefined",
        "noreturn", "void",         "anyopaque",      "anyerror",    "anytype",
        "anyframe", "comptime_int", "comptime_float", "isize",       "usize",
        "c_char",   "c_short",      "c_ushort",       "c_int",       "c_uint",
        "c_long",   "c_ulong",      "c_longlong",     "c_ulonglong", "c_longdouble",
        "f16",      "f32",          "f64",            "f80",         "f128",
    };
    for (primitives) |p| {
        if (std.mem.eql(u8, name, p)) return true;
    }
    // Check for integer types: i{N}, u{N} where N is digits
    if (name.len >= 2 and (name[0] == 'i' or name[0] == 'u')) {
        for (name[1..]) |c| {
            if (c < '0' or c > '9') return false;
        }
        return true;
    }
    return false;
}

fn isTypeAlias(self: *Linter, var_decl: Ast.full.VarDecl) bool {
    const init_node = var_decl.ast.init_node.unwrap() orelse return false;
    const tag = self.tree.nodeTag(init_node);
    return switch (tag) {
        .identifier => blk: {
            const token = self.tree.tokenSlice(self.tree.nodeMainToken(init_node));
            break :blk std.mem.eql(u8, token, "type") or isPascalCase(token) or isPrimitiveType(token);
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
                std.mem.eql(u8, token, "@Type") or
                std.mem.eql(u8, token, "@TypeOf");
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
        .merge_error_sets,
        // Type expressions
        .array_type,
        .array_type_sentinel,
        .ptr_type_aligned,
        .ptr_type_sentinel,
        .ptr_type,
        .ptr_type_bit_range,
        .optional_type,
        .error_union,
        .fn_proto,
        .fn_proto_multi,
        .fn_proto_one,
        .fn_proto_simple,
        => true,
        .block_two,
        .block_two_semicolon,
        .block,
        .block_semicolon,
        .@"if",
        .if_simple,
        .@"switch",
        .switch_comma,
        => blk: {
            // These expressions can return either types or values.
            // Use PascalCase name as heuristic for type alias.
            const name_token = var_decl.ast.mut_token + 1;
            const name = self.tree.tokenSlice(name_token);
            break :blk isPascalCase(name);
        },
        else => false,
    };
}

/// Checks if the variable declaration is a function alias (assigning a camelCase identifier).
/// Function aliases are allowed to use camelCase names.
fn isFunctionAlias(self: *Linter, var_decl: Ast.full.VarDecl) bool {
    const init_node = var_decl.ast.init_node.unwrap() orelse return false;
    const tag = self.tree.nodeTag(init_node);
    return switch (tag) {
        .identifier => blk: {
            const token = self.tree.tokenSlice(self.tree.nodeMainToken(init_node));
            break :blk isCamelCase(token);
        },
        .field_access => blk: {
            const data = self.tree.nodeData(init_node).node_and_token;
            const field_name = self.tree.tokenSlice(data[1]);
            break :blk isCamelCase(field_name);
        },
        else => false,
    };
}

fn isCamelCase(name: []const u8) bool {
    if (name.len == 0) return false;
    // Must start with lowercase letter
    if (name[0] < 'a' or name[0] > 'z') return false;
    // No underscores allowed
    for (name) |c| {
        if (c == '_') return false;
    }
    return true;
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

fn checkLineLength(self: *Linter) void {
    const max_len = self.config.getLineLength();
    var line_num: usize = 0;
    var line_start: usize = 0;

    for (self.source, 0..) |c, i| {
        if (c == '\n') {
            const line_len = i - line_start;
            if (line_len > max_len) {
                // Format: "actual_len\x00max_len" for the error message
                const context = std.fmt.allocPrint(self.allocator, "{}\x00{}", .{ line_len, max_len }) catch continue;
                self.allocated_contexts.append(self.allocator, context) catch {
                    self.allocator.free(context);
                    continue;
                };
                self.reportLineLength(line_num, context, max_len);
            }
            line_num += 1;
            line_start = i + 1;
        }
    }

    // Check last line if not terminated with newline
    if (line_start < self.source.len) {
        const line_len = self.source.len - line_start;
        if (line_len > max_len) {
            const context = std.fmt.allocPrint(self.allocator, "{}\x00{}", .{ line_len, max_len }) catch return;
            self.allocated_contexts.append(self.allocator, context) catch {
                self.allocator.free(context);
                return;
            };
            self.reportLineLength(line_num, context, max_len);
        }
    }
}

fn reportLineLength(self: *Linter, line: usize, context: []const u8, max_len: u32) void {
    if (self.isIgnored(line, .Z024)) return;

    self.diagnostics.append(self.allocator, .{
        .path = self.path,
        .line = @intCast(line + 1),
        .column = @intCast(max_len + 1),
        .rule = .Z024,
        .context = context,
        // ziglint-ignore: Z026
    }) catch {};
}

pub fn diagnosticCount(self: *const Linter, rule: rules.Rule) usize {
    var count: usize = 0;
    for (self.diagnostics.items) |d| {
        if (d.rule == rule) count += 1;
    }
    return count;
}

fn report(self: *Linter, loc: Ast.Location, rule: rules.Rule, context: []const u8) void {
    if (self.isIgnored(loc.line, rule)) return;

    self.diagnostics.append(self.allocator, .{
        .path = self.path,
        .line = @intCast(loc.line + 1),
        .column = @intCast(loc.column + 1),
        .rule = rule,
        .context = context,
        // ziglint-ignore: Z026
    }) catch {};
}

test "Z001: detect PascalCase function" {
    var linter: Linter = .init(std.testing.allocator, "fn MyFunc() void {}", "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnosticCount(.Z001));
}

test "Z001: allow camelCase function" {
    var linter: Linter = .init(std.testing.allocator, "fn myFunc() void {}", "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnosticCount(.Z001));
}

test "Z001: detect snake_case function" {
    var linter: Linter = .init(std.testing.allocator, "fn my_func() void {}", "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnosticCount(.Z001));
}

test "Z001: allow underscore prefix (private)" {
    var linter: Linter = .init(std.testing.allocator, "fn _privateFunc() void {}", "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnosticCount(.Z001));
}

test "Z001: allow single lowercase letter" {
    var linter: Linter = .init(std.testing.allocator, "fn f() void {}", "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnosticCount(.Z001));
}

test "Z002: detect unused variable with value" {
    var linter: Linter = .init(std.testing.allocator, "fn foo() void { const _x = 1; }", "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnosticCount(.Z002));
}

test "Z002: allow plain discard _" {
    var linter: Linter = .init(std.testing.allocator, "fn foo() void { const _ = bar(); }", "test.zig", null);
    defer linter.deinit();
    linter.lint();
    for (linter.diagnostics.items) |d| {
        try std.testing.expect(d.rule != rules.Rule.Z002);
    }
}

test "Z002: allow double underscore __" {
    var linter: Linter = .init(std.testing.allocator, "fn foo() void { const __x = 1; }", "test.zig", null);
    defer linter.deinit();
    linter.lint();
    for (linter.diagnostics.items) |d| {
        try std.testing.expect(d.rule != rules.Rule.Z002);
    }
}

test "Z003: detect parse error" {
    var linter: Linter = .init(std.testing.allocator, "const x = ", "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expect(linter.diagnostics.items.len > 0);
    try std.testing.expectEqual(rules.Rule.Z003, linter.diagnostics.items[0].rule);
}

test "Z003: valid code no parse error" {
    var linter: Linter = .init(std.testing.allocator, "const x: u32 = 42;", "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnosticCount(.Z003));
}

test "Z004: detect explicit struct init" {
    var linter: Linter = .init(std.testing.allocator, "const Foo = struct {}; fn bar() void { const x = Foo{}; _ = x; }", "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnosticCount(.Z004));
}

test "Z004: detect explicit struct init with fields" {
    var linter: Linter = .init(std.testing.allocator, "const Foo = struct { x: u32 }; fn bar() void { const f = Foo{ .x = 1 }; _ = f; }", "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnosticCount(.Z004));
}

test "Z004: allow anonymous struct init with type annotation" {
    var linter: Linter = .init(std.testing.allocator, "const Foo = struct {}; fn bar() void { const x: Foo = .{}; _ = x; }", "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnosticCount(.Z004));
}

test "Z004: allow anonymous struct init with fields" {
    var linter: Linter = .init(std.testing.allocator, "const Foo = struct { x: u32 }; fn bar() void { const f: Foo = .{ .x = 1 }; _ = f; }", "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnosticCount(.Z004));
}

test "Z005: detect lowercase type function" {
    var linter: Linter = .init(std.testing.allocator, "fn myType() type { return struct {}; }", "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnosticCount(.Z005));
}

test "Z005: detect snake_case type function" {
    var linter: Linter = .init(std.testing.allocator, "fn my_type() type { return struct {}; }", "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnosticCount(.Z005));
}

test "Z005: allow PascalCase type function" {
    var linter: Linter = .init(std.testing.allocator, "fn MyType() type { return struct {}; }", "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnosticCount(.Z005));
}

test "Z005: allow PascalCase generic type function" {
    var linter: Linter = .init(std.testing.allocator, "fn ArrayList(comptime T: type) type { return struct {}; }", "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnosticCount(.Z005));
}

test "Z006: detect camelCase variable" {
    var linter: Linter = .init(std.testing.allocator, "fn foo() void { const myVar = 1; _ = myVar; }", "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnosticCount(.Z006));
}

test "Z006: detect PascalCase variable (not type)" {
    var linter: Linter = .init(std.testing.allocator, "fn foo() void { const MyVar = 1; _ = MyVar; }", "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnosticCount(.Z006));
}

test "Z006: allow snake_case variable" {
    var linter: Linter = .init(std.testing.allocator, "fn foo() void { const my_var = 1; _ = my_var; }", "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnosticCount(.Z006));
}

test "Z006: allow single lowercase letter" {
    var linter: Linter = .init(std.testing.allocator, "fn foo() void { const x = 1; _ = x; }", "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnosticCount(.Z006));
}

test "Z006: allow underscore prefix" {
    var linter: Linter = .init(std.testing.allocator, "fn foo() void { const _unused: u32 = undefined; _ = _unused; }", "test.zig", null);
    defer linter.deinit();
    linter.lint();
    for (linter.diagnostics.items) |d| {
        try std.testing.expect(d.rule != rules.Rule.Z006);
    }
}

test "Z006: allow type alias with @This()" {
    var linter: Linter = .init(std.testing.allocator, "const MyType = @This();", "MyType.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnosticCount(.Z006));
}

test "Z006: allow type alias with @import()" {
    var linter: Linter = .init(std.testing.allocator, "const Foo = @import(\"foo.zig\");", "test.zig", null);
    defer linter.deinit();
    linter.lint();
    for (linter.diagnostics.items) |d| {
        try std.testing.expect(d.rule != rules.Rule.Z006);
    }
}

test "Z006: allow type alias with @Type()" {
    var linter: Linter = .init(std.testing.allocator, "const MyType = @Type(.{ .int = .{ .signedness = .unsigned, .bits = 8 } });", "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnosticCount(.Z006));
}

test "Z006: allow type alias with @TypeOf()" {
    var linter: Linter = .init(std.testing.allocator, "fn foo(value: anytype) void { const T = @TypeOf(value); _ = T; }", "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnosticCount(.Z006));
}

test "Z006: allow type alias with struct" {
    var linter: Linter = .init(std.testing.allocator, "const MyStruct = struct { x: u32 };", "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnosticCount(.Z006));
}

test "Z006: allow type alias with enum" {
    var linter: Linter = .init(std.testing.allocator, "const MyEnum = enum { a, b, c };", "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnosticCount(.Z006));
}

test "Z006: allow type alias with union" {
    var linter: Linter = .init(std.testing.allocator, "const MyUnion = union { x: u32, y: f32 };", "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnosticCount(.Z006));
}

test "Z006: allow error set type" {
    var linter: Linter = .init(std.testing.allocator, "const Oom = error{OutOfMemory};", "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnosticCount(.Z006));
}

test "Z006: allow type function call" {
    var linter: Linter = .init(std.testing.allocator, "fn GenericType(comptime T: type) type { return struct {}; } const MyType = GenericType(u32);", "test.zig", null);
    defer linter.deinit();
    linter.lint();
    for (linter.diagnostics.items) |d| {
        try std.testing.expect(d.rule != rules.Rule.Z006);
    }
}

test "Z006: allow type alias with field access ending in PascalCase" {
    var linter: Linter = .init(std.testing.allocator, "const std = @import(\"std\"); const Ast = std.zig.Ast;", "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnosticCount(.Z006));
}

test "Z006: detect field access ending in snake_case" {
    var linter: Linter = .init(std.testing.allocator, "const std = @import(\"std\"); const Thing = std.some_value;", "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnosticCount(.Z006));
}

test "Z006: allow PascalCase identifier assignment" {
    var linter: Linter = .init(std.testing.allocator, "const MyType = SomeType;", "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnosticCount(.Z006));
}

test "Z006: allow type alias with primitive type" {
    var linter: Linter = .init(std.testing.allocator, "const Days = i32; const Nanoseconds = i128; const Float = f64;", "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnosticCount(.Z006));
}

test "Z006: allow PascalCase labeled block type alias" {
    var linter: Linter = .init(std.testing.allocator,
        \\const Config = blk: {
        \\    break :blk @Type(.{ .@"struct" = .{
        \\        .layout = .auto,
        \\        .fields = &.{},
        \\        .decls = &.{},
        \\        .is_tuple = false,
        \\    } });
        \\};
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnosticCount(.Z006));
}

test "Z006: detect camelCase labeled block (not type)" {
    var linter: Linter = .init(std.testing.allocator,
        \\const myValue = blk: {
        \\    break :blk 42;
        \\};
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnosticCount(.Z006));
}

test "Z006: detect snake_case identifier assignment" {
    var linter: Linter = .init(std.testing.allocator, "const MyThing = some_value;", "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnosticCount(.Z006));
}

test "Z006: allow type alias with array type" {
    var linter: Linter = .init(std.testing.allocator, "const Buffer = [8192]u8;", "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnosticCount(.Z006));
}

test "Z006: allow type alias with sentinel array type" {
    var linter: Linter = .init(std.testing.allocator, "const CString = [*:0]const u8;", "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnosticCount(.Z006));
}

test "Z006: allow type alias with pointer type" {
    var linter: Linter = .init(std.testing.allocator, "const BytePtr = *const u8;", "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnosticCount(.Z006));
}

test "Z006: allow type alias with optional type" {
    var linter: Linter = .init(std.testing.allocator, "const MaybeInt = ?i32;", "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnosticCount(.Z006));
}

test "Z006: allow type alias with error union type" {
    var linter: Linter = .init(std.testing.allocator, "const Result = anyerror!i32;", "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnosticCount(.Z006));
}

test "Z006: allow type alias with function pointer type" {
    var linter: Linter = .init(std.testing.allocator, "const Handler = *const fn (*u8) anyerror!void;", "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnosticCount(.Z006));
}

test "Z006: allow type alias with bare function type" {
    var linter: Linter = .init(std.testing.allocator, "const Callback = fn (i32) void;", "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnosticCount(.Z006));
}

test "Z006: allow PascalCase comptime if type alias" {
    var linter: Linter = .init(std.testing.allocator, "const ThreadPool = if (true) u32 else void;", "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnosticCount(.Z006));
}

test "Z006: detect camelCase comptime if (not type)" {
    var linter: Linter = .init(std.testing.allocator, "const threadPool = if (true) u32 else void;", "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnosticCount(.Z006));
}

test "Z006: allow PascalCase switch type alias" {
    var linter: Linter = .init(std.testing.allocator, "const MyType = switch (x) { .a => u32, .b => i32 };", "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnosticCount(.Z006));
}

test "Z006: detect camelCase switch (not type)" {
    var linter: Linter = .init(std.testing.allocator, "const myValue = switch (x) { .a => 1, .b => 2 };", "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnosticCount(.Z006));
}

test "Z006: allow camelCase function alias" {
    var linter: Linter = .init(std.testing.allocator, "fn fooBar() void {} const myAlias = fooBar;", "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnosticCount(.Z006));
}

test "Z006: allow camelCase function alias with field access" {
    var linter: Linter = .init(std.testing.allocator, "const std = @import(\"std\"); const myAlias = std.someFunc;", "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnosticCount(.Z006));
}

test "inline ignore: single rule" {
    var linter: Linter = .init(std.testing.allocator, "fn foo() void { const myVar = 1; _ = myVar; } // ziglint-ignore: Z006", "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnosticCount(.Z006));
}

test "inline ignore: multiple rules" {
    var linter: Linter = .init(std.testing.allocator, "fn MyFunc() void { const myVar = 1; _ = myVar; } // ziglint-ignore: Z001 Z006", "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnosticCount(.Z001));
    try std.testing.expectEqual(0, linter.diagnosticCount(.Z006));
}

test "inline ignore: only ignores specified rule" {
    var linter: Linter = .init(std.testing.allocator, "fn MyFunc() void {} // ziglint-ignore: Z006", "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnosticCount(.Z001));
    try std.testing.expectEqual(0, linter.diagnosticCount(.Z006));
}

test "inline ignore: multiline - only affects that line" {
    var linter: Linter = .init(std.testing.allocator,
        \\fn MyFunc() void {} // ziglint-ignore: Z001
        \\fn AnotherBad() void {}
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnosticCount(.Z001));
}

test "inline ignore: preceding line comment" {
    var linter: Linter = .init(std.testing.allocator,
        \\// ziglint-ignore: Z001
        \\fn MyFunc() void {}
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnosticCount(.Z001));
}

test "inline ignore: preceding line only affects next line" {
    var linter: Linter = .init(std.testing.allocator,
        \\// ziglint-ignore: Z001
        \\fn MyFunc() void {}
        \\fn AnotherBad() void {}
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnosticCount(.Z001));
}

test "inline ignore: multiple preceding comment lines" {
    var linter: Linter = .init(std.testing.allocator,
        \\// ziglint-ignore: Z001
        \\// ziglint-ignore: Z006
        \\fn MyFunc() void { const myVar = 1; _ = myVar; }
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnosticCount(.Z001));
    try std.testing.expectEqual(0, linter.diagnosticCount(.Z006));
}

test "inline ignore: multiple preceding with other comments" {
    var linter: Linter = .init(std.testing.allocator,
        \\// ziglint-ignore: Z001
        \\// This function does something important
        \\// ziglint-ignore: Z006
        \\fn MyFunc() void { const myVar = 1; _ = myVar; }
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnosticCount(.Z001));
    try std.testing.expectEqual(0, linter.diagnosticCount(.Z006));
}

test "Z007: duplicate import" {
    var linter: Linter = .init(std.testing.allocator,
        \\const std = @import("std");
        \\const std2 = @import("std");
        \\const x = std;
        \\const y = std2;
    , "test.zig", null);
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
    , "test.zig", null);
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
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    var z007_count: usize = 0;
    for (linter.diagnostics.items) |d| {
        if (d.rule == rules.Rule.Z007) z007_count += 1;
    }
    try std.testing.expectEqual(2, z007_count);
}

test "Z009: file with top-level fields needs PascalCase name" {
    var linter: Linter = .init(std.testing.allocator, "foo: u32 = 0,", "my_module.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnostics.items.len);
    try std.testing.expectEqual(rules.Rule.Z009, linter.diagnostics.items[0].rule);
}

test "Z009: file with top-level fields and PascalCase name is ok" {
    var linter: Linter = .init(std.testing.allocator, "foo: u32 = 0,", "MyModule.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnostics.items.len);
}

test "Z009: file without top-level fields can be lowercase" {
    var linter: Linter = .init(std.testing.allocator, "const x: u32 = 0;", "main.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnosticCount(.Z009));
}

test "Z010: detect explicit struct in return" {
    var linter: Linter = .init(std.testing.allocator, "fn foo() Foo { return Foo{}; }", "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnosticCount(.Z010));
}

test "Z010: allow anonymous struct in return" {
    var linter: Linter = .init(std.testing.allocator, "fn foo() Foo { return .{}; }", "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnosticCount(.Z010));
}

test "Z010: detect explicit struct in function arg" {
    var linter: Linter = .init(std.testing.allocator, "fn bar(x: Foo) void {} fn foo() void { bar(Foo{}); }", "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnosticCount(.Z010));
}

test "Z010: allow anonymous struct in function arg" {
    var linter: Linter = .init(std.testing.allocator, "fn bar(x: Foo) void {} fn foo() void { bar(.{}); }", "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnosticCount(.Z010));
}

test "Z010: detect explicit enum in return" {
    var linter: Linter = .init(std.testing.allocator, "fn foo() Mode { return Mode.fast; }", "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnosticCount(.Z010));
}

test "Z010: allow anonymous enum in return" {
    var linter: Linter = .init(std.testing.allocator, "fn foo() Mode { return .fast; }", "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnosticCount(.Z010));
}

test "Z010: allow field access on non-type (self.field)" {
    var linter: Linter = .init(std.testing.allocator, "fn foo(self: *Self) u32 { return self.value; }", "test.zig", null);
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

    var linter: Linter = .initWithSemantics(std.testing.allocator, source, path, &resolver, path, null);
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

    var linter: Linter = .initWithSemantics(std.testing.allocator, source, path, &resolver, path, null);
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

    var linter: Linter = .init(std.testing.allocator, source, "test.zig", null);
    defer linter.deinit();
    linter.lint();

    for (linter.diagnostics.items) |d| {
        try std.testing.expect(d.rule != rules.Rule.Z011);
    }
}

test "Z011: detect deprecated direct function call" {
    const ModuleGraph = @import("ModuleGraph.zig");
    const source =
        \\/// Deprecated: use newFunc instead
        \\pub fn oldFunc() void {}
        \\pub fn main() void {
        \\    oldFunc();
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

    var linter: Linter = .initWithSemantics(std.testing.allocator, source, path, &resolver, path, null);
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

test "Z011: detect deprecated function alias" {
    const ModuleGraph = @import("ModuleGraph.zig");
    const source =
        \\/// Deprecated: use newFunc instead
        \\pub fn oldFunc() void {}
        \\pub const aliasFunc = oldFunc;
        \\pub fn main() void {
        \\    aliasFunc();
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

    var linter: Linter = .initWithSemantics(std.testing.allocator, source, path, &resolver, path, null);
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

test "Z011: detect deprecated type function" {
    const ModuleGraph = @import("ModuleGraph.zig");
    const source =
        \\/// Deprecated: use NewList instead
        \\pub fn OldList(comptime T: type) type {
        \\    return struct { items: []T };
        \\}
        \\pub fn main() void {
        \\    _ = OldList(u8);
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

    var linter: Linter = .initWithSemantics(std.testing.allocator, source, path, &resolver, path, null);
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

test "Z011: detect deprecated type function alias" {
    const ModuleGraph = @import("ModuleGraph.zig");
    const source =
        \\/// Deprecated: use NewList instead
        \\pub fn OldList(comptime T: type) type {
        \\    return struct { items: []T };
        \\}
        \\pub const DeprecatedAlias = OldList;
        \\pub fn main() void {
        \\    _ = DeprecatedAlias(u8);
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

    var linter: Linter = .initWithSemantics(std.testing.allocator, source, path, &resolver, path, null);
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

test "Z011: detect deprecated stdlib function (ArrayListUnmanaged)" {
    const ModuleGraph = @import("ModuleGraph.zig");

    // Detect zig lib path by running zig env
    const zig_lib_path = blk: {
        var child: std.process.Child = .init(&.{ "zig", "env" }, std.testing.allocator);
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Ignore;
        child.spawn() catch break :blk null;

        var buf: [64 * 1024]u8 = undefined;
        const stdout = child.stdout orelse break :blk null;
        const len = stdout.readAll(&buf) catch break :blk null;
        const output = buf[0..len];

        const term = child.wait() catch break :blk null;
        switch (term) {
            .Exited => |code| if (code != 0) break :blk null,
            else => break :blk null,
        }

        const needle = ".lib_dir = \"";
        const start_idx = std.mem.indexOf(u8, output, needle) orelse break :blk null;
        const value_start = start_idx + needle.len;
        const end_idx = std.mem.indexOfPos(u8, output, value_start, "\"") orelse break :blk null;
        break :blk std.testing.allocator.dupe(u8, output[value_start..end_idx]) catch null;
    };

    // Skip test if zig isn't available
    if (zig_lib_path == null) return;
    defer std.testing.allocator.free(zig_lib_path.?);

    const source =
        \\const std = @import("std");
        \\pub fn main() void {
        \\    _ = std.ArrayListUnmanaged(u8);
        \\}
    ;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    try tmp_dir.dir.writeFile(.{ .sub_path = "test.zig", .data = source });
    const path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, "test.zig");
    defer std.testing.allocator.free(path);

    var graph = try ModuleGraph.init(std.testing.allocator, path, zig_lib_path);
    defer graph.deinit();

    var resolver: TypeResolver = .init(std.testing.allocator, &graph);
    defer resolver.deinit();

    var linter: Linter = .initWithSemantics(std.testing.allocator, source, path, &resolver, path, null);
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

test "Z011: deprecated stdlib corpus - real Zig 0.15.2 deprecations" {
    const ModuleGraph = @import("ModuleGraph.zig");

    // Detect zig lib path by running zig env
    const zig_lib_path = blk: {
        var child: std.process.Child = .init(&.{ "zig", "env" }, std.testing.allocator);
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Ignore;
        child.spawn() catch break :blk null;

        var buf: [64 * 1024]u8 = undefined;
        const stdout = child.stdout orelse break :blk null;
        const len = stdout.readAll(&buf) catch break :blk null;
        const output = buf[0..len];

        const term = child.wait() catch break :blk null;
        switch (term) {
            .Exited => |code| if (code != 0) break :blk null,
            else => break :blk null,
        }

        const needle = ".lib_dir = \"";
        const start_idx = std.mem.indexOf(u8, output, needle) orelse break :blk null;
        const value_start = start_idx + needle.len;
        const end_idx = std.mem.indexOfPos(u8, output, value_start, "\"") orelse break :blk null;
        break :blk std.testing.allocator.dupe(u8, output[value_start..end_idx]) catch null;
    };

    // Skip test if zig isn't available
    if (zig_lib_path == null) return;
    defer std.testing.allocator.free(zig_lib_path.?);

    // Test cases: each uses a real deprecated function from Zig 0.15.2 stdlib
    const test_cases = [_]struct {
        name: []const u8,
        source: [:0]const u8,
        expected_count: usize, // Minimum number of Z011 warnings expected
    }{
        .{
            .name = "std.mem.copyBackwards",
            .source =
            \\const std = @import("std");
            \\pub fn main() void {
            \\    var dest: [5]u8 = undefined;
            \\    const src = [_]u8{ 1, 2, 3, 4, 5 };
            \\    std.mem.copyBackwards(u8, &dest, &src);
            \\}
            ,
            .expected_count = 1,
        },
        .{
            .name = "std.meta.intToEnum",
            .source =
            \\const std = @import("std");
            \\const MyEnum = enum { a, b, c };
            \\pub fn main() !void {
            \\    _ = try std.meta.intToEnum(MyEnum, 1);
            \\}
            ,
            .expected_count = 0, // TODO: Not yet detected - needs investigation
        },
        .{
            .name = "std.meta.TagPayload",
            .source =
            \\const std = @import("std");
            \\const U = union(enum) { a: u32, b: []const u8 };
            \\pub fn main() void {
            \\    const T = std.meta.TagPayload(U, U.a);
            \\    _ = T;
            \\}
            ,
            .expected_count = 1,
        },
        .{
            .name = "std.Io.null_writer",
            .source =
            \\const std = @import("std");
            \\pub fn main() void {
            \\    _ = std.Io.null_writer;
            \\}
            ,
            .expected_count = 0, // TODO: This is a const value, not a function call
        },
        .{
            .name = "std.ArrayListAligned",
            .source =
            \\const std = @import("std");
            \\pub fn main() void {
            \\    _ = std.ArrayListAligned(u8, 8);
            \\}
            ,
            .expected_count = 1,
        },
    };

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    for (test_cases) |tc| {
        try tmp_dir.dir.writeFile(.{ .sub_path = "test.zig", .data = tc.source });
        const path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, "test.zig");
        defer std.testing.allocator.free(path);

        var graph = try ModuleGraph.init(std.testing.allocator, path, zig_lib_path);
        defer graph.deinit();

        var resolver: TypeResolver = .init(std.testing.allocator, &graph);
        defer resolver.deinit();

        var linter: Linter = .initWithSemantics(std.testing.allocator, tc.source, path, &resolver, path, null);
        defer linter.deinit();

        linter.lint();

        var z011_count: usize = 0;
        for (linter.diagnostics.items) |d| {
            if (d.rule == rules.Rule.Z011) {
                z011_count += 1;
            }
        }

        std.debug.print("Test case '{s}': expected >={d}, got {d} ", .{ tc.name, tc.expected_count, z011_count });
        if (z011_count < tc.expected_count) {
            std.debug.print("FAIL\n", .{});
            std.debug.print("  All diagnostics:\n", .{});
            for (linter.diagnostics.items) |d| {
                std.debug.print("    {s}: line {d}\n", .{ d.rule.code(), d.line });
            }
        } else {
            std.debug.print("PASS\n", .{});
        }
        try std.testing.expect(z011_count >= tc.expected_count);
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
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnostics.items.len);
    try std.testing.expectEqual(rules.Rule.Z012, linter.diagnostics.items[0].rule);
}

test "Z012: pub fn accepting private type parameter" {
    var linter: Linter = .init(std.testing.allocator,
        \\const Private = struct {};
        \\pub fn usePrivate(p: Private) void { _ = p; }
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnostics.items.len);
    try std.testing.expectEqual(rules.Rule.Z012, linter.diagnostics.items[0].rule);
}

test "Z012: pub fn returning optional private type" {
    var linter: Linter = .init(std.testing.allocator,
        \\const Private = struct {};
        \\pub fn maybePrivate() ?Private { return null; }
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnostics.items.len);
    try std.testing.expectEqual(rules.Rule.Z012, linter.diagnostics.items[0].rule);
}

test "Z012: pub fn returning error union with private type" {
    var linter: Linter = .init(std.testing.allocator,
        \\const Private = struct {};
        \\pub fn getPrivateOrError() !Private {
        \\    if (false) return error.Fail;
        \\    return .{};
        \\}
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnostics.items.len);
    try std.testing.expectEqual(rules.Rule.Z012, linter.diagnostics.items[0].rule);
}

test "Z015: pub fn returning private error set" {
    var linter: Linter = .init(std.testing.allocator,
        \\const Oom = error{OutOfMemory};
        \\pub fn doThing() Oom!void {
        \\    return error.OutOfMemory;
        \\}
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnostics.items.len);
    try std.testing.expectEqual(rules.Rule.Z015, linter.diagnostics.items[0].rule);
}

test "Z012: pub fn returning public type is ok" {
    var linter: Linter = .init(std.testing.allocator,
        \\pub const Public = struct {};
        \\pub fn getPublic() Public { return .{}; }
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    for (linter.diagnostics.items) |d| {
        try std.testing.expect(d.rule != rules.Rule.Z012);
    }
}

test "Z012: pub fn using pub type from enclosing struct is ok" {
    var linter: Linter = .init(std.testing.allocator,
        \\const Foo = struct {
        \\    pub const Inner = struct {};
        \\    pub fn a(i: Inner) void { _ = i; }
        \\    pub fn getInner() Inner { return .{}; }
        \\};
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    for (linter.diagnostics.items) |d| {
        try std.testing.expect(d.rule != rules.Rule.Z012);
    }
}

test "Z012: pub fn using non-pub type from enclosing struct is error" {
    var linter: Linter = .init(std.testing.allocator,
        \\const Foo = struct {
        \\    const Inner = struct {};
        \\    pub fn a(i: Inner) void { _ = i; }
        \\};
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnostics.items.len);
    try std.testing.expectEqual(rules.Rule.Z012, linter.diagnostics.items[0].rule);
}

test "Z012: pub fn returning builtin type is ok" {
    var linter: Linter = .init(std.testing.allocator,
        \\pub fn getValue() u32 { return 42; }
    , "test.zig", null);
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
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    for (linter.diagnostics.items) |d| {
        try std.testing.expect(d.rule != rules.Rule.Z012);
    }
}

test "Z012: generic parameter with comptime T: type is ok" {
    var linter: Linter = .init(std.testing.allocator,
        \\pub fn genericFn(comptime T: type) T { return undefined; }
    , "test.zig", null);
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
    , "test.zig", null);
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
    , "test.zig", null);
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
    , "test.zig", null);
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
    , "test.zig", null);
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
    , "test.zig", null);
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
    , "test.zig", null);
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
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    for (linter.diagnostics.items) |d| {
        try std.testing.expect(d.rule != rules.Rule.Z012);
    }
}

test "Z013: detect unused import" {
    var linter: Linter = .init(std.testing.allocator,
        \\const foo = @import("foo.zig");
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnostics.items.len);
    try std.testing.expectEqual(rules.Rule.Z013, linter.diagnostics.items[0].rule);
}

test "Z013: import used via field access is ok" {
    var linter: Linter = .init(std.testing.allocator,
        \\const std = @import("std");
        \\const mem = std.mem;
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    for (linter.diagnostics.items) |d| {
        try std.testing.expect(d.rule != rules.Rule.Z013);
    }
}

test "Z013: discarded import at root should warn" {
    var linter: Linter = .init(std.testing.allocator,
        \\const _ = @import("foo.zig");
    , "test.zig", null);
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
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    for (linter.diagnostics.items) |d| {
        try std.testing.expect(d.rule != rules.Rule.Z013);
    }
}

test "Z013: pub re-export is not unused" {
    var linter: Linter = .init(std.testing.allocator,
        \\pub const foo = @import("foo.zig");
    , "test.zig", null);
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
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    for (linter.diagnostics.items) |d| {
        try std.testing.expect(d.rule != rules.Rule.Z013);
    }
}

test "Z014: detect snake_case error set" {
    var linter: Linter = .init(std.testing.allocator, "const my_error = error{OutOfMemory};", "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnosticCount(.Z014));
}

test "Z014: allow PascalCase error set" {
    var linter: Linter = .init(std.testing.allocator, "const Oom = error{OutOfMemory};", "test.zig", null);
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
    , "test.zig", null);
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
    , "test.zig", null);
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
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    for (linter.diagnostics.items) |d| {
        try std.testing.expect(d.rule != rules.Rule.Z016);
    }
}

test "Z019: @This() in named struct should warn" {
    var linter: Linter = .init(std.testing.allocator,
        \\const Foo = struct {
        \\    const Self = @This();
        \\};
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    var found = false;
    for (linter.diagnostics.items) |d| {
        if (d.rule == rules.Rule.Z019) {
            found = true;
            try std.testing.expectEqualStrings("Foo", d.context);
        }
    }
    try std.testing.expect(found);
}

test "Z019: @This() in anonymous struct is ok" {
    var linter: Linter = .init(std.testing.allocator,
        \\fn Generic(comptime T: type) type {
        \\    _ = T;
        \\    return struct {
        \\        const Self = @This();
        \\    };
        \\}
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    for (linter.diagnostics.items) |d| {
        try std.testing.expect(d.rule != rules.Rule.Z019);
    }
}

test "Z019: nested named struct should warn" {
    var linter: Linter = .init(std.testing.allocator,
        \\const Outer = struct {
        \\    const Inner = struct {
        \\        const Self = @This();
        \\    };
        \\};
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    var found = false;
    for (linter.diagnostics.items) |d| {
        if (d.rule == rules.Rule.Z019) {
            found = true;
            try std.testing.expectEqualStrings("Inner", d.context);
        }
    }
    try std.testing.expect(found);
}

test "Z019: @This() in local struct (inside fn) is ok" {
    var linter: Linter = .init(std.testing.allocator,
        \\fn foo() void {
        \\    const Local = struct {
        \\        const Self = @This();
        \\    };
        \\    _ = Local;
        \\}
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    for (linter.diagnostics.items) |d| {
        try std.testing.expect(d.rule != rules.Rule.Z019);
    }
}

test "Z019: @This() in local struct (inside test) is ok" {
    var linter: Linter = .init(std.testing.allocator,
        \\test {
        \\    const Local = struct {
        \\        const Self = @This();
        \\    };
        \\    _ = Local;
        \\}
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    for (linter.diagnostics.items) |d| {
        try std.testing.expect(d.rule != rules.Rule.Z019);
    }
}

test "Z019: @This() in local struct inside nested if blocks is ok" {
    var linter: Linter = .init(std.testing.allocator,
        \\fn foo() void {
        \\    if (true) {
        \\        if (true) {
        \\            if (true) {
        \\                const Local = struct {
        \\                    const Self = @This();
        \\                };
        \\                _ = Local;
        \\            }
        \\        }
        \\    }
        \\}
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    for (linter.diagnostics.items) |d| {
        try std.testing.expect(d.rule != rules.Rule.Z019);
    }
}

test "Z020: inline @This() should warn" {
    var linter: Linter = .init(std.testing.allocator,
        \\const Foo = struct {
        \\    fn method() @This() { return undefined; }
        \\};
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    var found = false;
    for (linter.diagnostics.items) |d| {
        if (d.rule == rules.Rule.Z020) found = true;
    }
    try std.testing.expect(found);
}

test "Z020: @This() as function argument is ok" {
    var linter: Linter = .init(std.testing.allocator,
        \\const std = @import("std");
        \\test {
        \\    std.testing.refAllDecls(@This());
        \\}
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    for (linter.diagnostics.items) |d| {
        try std.testing.expect(d.rule != rules.Rule.Z020);
    }
}

test "Z021: file-struct @This() alias should match filename or Self" {
    var linter: Linter = .init(std.testing.allocator,
        \\const SelfType = @This();
        \\value: u32,
    , "Writer.zig", null);
    defer linter.deinit();
    linter.lint();
    var found = false;
    for (linter.diagnostics.items) |d| {
        if (d.rule == rules.Rule.Z021) found = true;
    }
    try std.testing.expect(found);
}

test "Z021: file-struct @This() alias matching filename is ok" {
    var linter: Linter = .init(std.testing.allocator,
        \\const Writer = @This();
        \\value: u32,
    , "Writer.zig", null);
    defer linter.deinit();
    linter.lint();
    for (linter.diagnostics.items) |d| {
        try std.testing.expect(d.rule != rules.Rule.Z021);
    }
}

test "Z021: file-struct @This() alias Self is ok" {
    var linter: Linter = .init(std.testing.allocator,
        \\const Self = @This();
        \\value: u32,
    , "Writer.zig", null);
    defer linter.deinit();
    linter.lint();
    for (linter.diagnostics.items) |d| {
        try std.testing.expect(d.rule != rules.Rule.Z021);
    }
}

test "Z022: anonymous struct @This() alias should be Self" {
    var linter: Linter = .init(std.testing.allocator,
        \\fn Generic(comptime T: type) type {
        \\    _ = T;
        \\    return struct {
        \\        const This = @This();
        \\    };
        \\}
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    var found = false;
    for (linter.diagnostics.items) |d| {
        if (d.rule == rules.Rule.Z022) {
            found = true;
            try std.testing.expectEqualStrings("This", d.context);
        }
    }
    try std.testing.expect(found);
}

test "Z022: anonymous struct @This() alias Self is ok" {
    var linter: Linter = .init(std.testing.allocator,
        \\fn Generic(comptime T: type) type {
        \\    _ = T;
        \\    return struct {
        \\        const Self = @This();
        \\    };
        \\}
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    for (linter.diagnostics.items) |d| {
        try std.testing.expect(d.rule != rules.Rule.Z022);
    }
}

test "Z022: local struct @This() alias should be Self" {
    var linter: Linter = .init(std.testing.allocator,
        \\fn foo() void {
        \\    const Local = struct {
        \\        const This = @This();
        \\    };
        \\    _ = Local;
        \\}
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    var found = false;
    for (linter.diagnostics.items) |d| {
        if (d.rule == rules.Rule.Z022) found = true;
    }
    try std.testing.expect(found);
}

test "Z023: argument order - allocator before type param" {
    var linter: Linter = .init(std.testing.allocator,
        \\const std = @import("std");
        \\fn bad(allocator: std.mem.Allocator, comptime T: type) void {
        \\    _ = .{ allocator, T };
        \\}
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    var found = false;
    for (linter.diagnostics.items) |d| {
        if (d.rule == rules.Rule.Z023) found = true;
    }
    try std.testing.expect(found);
}

test "Z023: argument order - io before allocator" {
    var linter: Linter = .init(std.testing.allocator,
        \\const std = @import("std");
        \\fn bad(io: std.Io, allocator: std.mem.Allocator) void {
        \\    _ = .{ io, allocator };
        \\}
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    var found = false;
    for (linter.diagnostics.items) |d| {
        if (d.rule == rules.Rule.Z023) found = true;
    }
    try std.testing.expect(found);
}

test "Z023: argument order - correct order is ok" {
    var linter: Linter = .init(std.testing.allocator,
        \\const std = @import("std");
        \\fn good(comptime T: type, allocator: std.mem.Allocator, io: std.Io, value: u32) void {
        \\    _ = .{ T, allocator, io, value };
        \\}
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    for (linter.diagnostics.items) |d| {
        try std.testing.expect(d.rule != rules.Rule.Z023);
    }
}

test "Z023: argument order - aliased Allocator" {
    const source =
        \\const std = @import("std");
        \\const Alloc = std.mem.Allocator;
        \\fn bad(value: u32, alloc: Alloc) void {
        \\    _ = .{ value, alloc };
        \\}
    ;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    try tmp_dir.dir.writeFile(.{ .sub_path = "test.zig", .data = source });
    const path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, "test.zig");
    defer std.testing.allocator.free(path);

    const ModuleGraph = @import("ModuleGraph.zig");
    var graph = try ModuleGraph.init(std.testing.allocator, path, null);
    defer graph.deinit();

    var resolver: TypeResolver = .init(std.testing.allocator, &graph);
    defer resolver.deinit();

    var linter: Linter = .initWithSemantics(std.testing.allocator, source, path, &resolver, path, null);
    defer linter.deinit();
    linter.lint();

    var found = false;
    for (linter.diagnostics.items) |d| {
        if (d.rule == rules.Rule.Z023) found = true;
    }
    try std.testing.expect(found);
}

test "Z023: argument order - aliased Io" {
    const source =
        \\const std = @import("std");
        \\const MyIo = std.Io;
        \\fn bad(value: u32, io: MyIo) void {
        \\    _ = .{ value, io };
        \\}
    ;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    try tmp_dir.dir.writeFile(.{ .sub_path = "test.zig", .data = source });
    const path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, "test.zig");
    defer std.testing.allocator.free(path);

    const ModuleGraph = @import("ModuleGraph.zig");
    var graph = try ModuleGraph.init(std.testing.allocator, path, null);
    defer graph.deinit();

    var resolver: TypeResolver = .init(std.testing.allocator, &graph);
    defer resolver.deinit();

    var linter: Linter = .initWithSemantics(std.testing.allocator, source, path, &resolver, path, null);
    defer linter.deinit();
    linter.lint();

    var found = false;
    for (linter.diagnostics.items) |d| {
        if (d.rule == rules.Rule.Z023) found = true;
    }
    try std.testing.expect(found);
}

test "Z023: receiver param with @This() is ok" {
    var linter: Linter = .init(std.testing.allocator,
        \\const std = @import("std");
        \\const Foo = struct {
        \\    pub fn bar(self: *@This(), alloc: std.mem.Allocator) void {
        \\        _ = .{ self, alloc };
        \\    }
        \\};
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    for (linter.diagnostics.items) |d| {
        try std.testing.expect(d.rule != rules.Rule.Z023);
    }
}

test "Z023: receiver param with Self is ok" {
    var linter: Linter = .init(std.testing.allocator,
        \\const std = @import("std");
        \\const Foo = struct {
        \\    const Self = @This();
        \\    pub fn bar(self: *Self, alloc: std.mem.Allocator) void {
        \\        _ = .{ self, alloc };
        \\    }
        \\};
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    for (linter.diagnostics.items) |d| {
        try std.testing.expect(d.rule != rules.Rule.Z023);
    }
}

test "Z023: receiver param with struct name is ok (semantic)" {
    const source =
        \\const std = @import("std");
        \\const Foo = struct {
        \\    pub fn bar(self: *Foo, alloc: std.mem.Allocator) void {
        \\        _ = .{ self, alloc };
        \\    }
        \\};
    ;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    try tmp_dir.dir.writeFile(.{ .sub_path = "test.zig", .data = source });
    const path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, "test.zig");
    defer std.testing.allocator.free(path);

    const ModuleGraph = @import("ModuleGraph.zig");
    var graph = try ModuleGraph.init(std.testing.allocator, path, null);
    defer graph.deinit();

    var resolver: TypeResolver = .init(std.testing.allocator, &graph);
    defer resolver.deinit();

    var linter: Linter = .initWithSemantics(std.testing.allocator, source, path, &resolver, path, null);
    defer linter.deinit();
    linter.lint();

    for (linter.diagnostics.items) |d| {
        try std.testing.expect(d.rule != rules.Rule.Z023);
    }
}

test "Z023: file-as-struct receiver is ok (semantic)" {
    const source =
        \\const std = @import("std");
        \\const Terminal = @This();
        \\pub fn deinit(self: *Terminal, alloc: std.mem.Allocator) void {
        \\    _ = .{ self, alloc };
        \\}
    ;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    try tmp_dir.dir.writeFile(.{ .sub_path = "Terminal.zig", .data = source });
    const path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, "Terminal.zig");
    defer std.testing.allocator.free(path);

    const ModuleGraph = @import("ModuleGraph.zig");
    var graph = try ModuleGraph.init(std.testing.allocator, path, null);
    defer graph.deinit();

    var resolver: TypeResolver = .init(std.testing.allocator, &graph);
    defer resolver.deinit();

    var linter: Linter = .initWithSemantics(std.testing.allocator, source, path, &resolver, path, null);
    defer linter.deinit();
    linter.lint();

    for (linter.diagnostics.items) |d| {
        try std.testing.expect(d.rule != rules.Rule.Z023);
    }
}

test "Z023: non-receiver first param still checked" {
    var linter: Linter = .init(std.testing.allocator,
        \\const std = @import("std");
        \\fn bad(value: u32, alloc: std.mem.Allocator) void {
        \\    _ = .{ value, alloc };
        \\}
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    var found = false;
    for (linter.diagnostics.items) |d| {
        if (d.rule == rules.Rule.Z023) found = true;
    }
    try std.testing.expect(found);
}

test "Z023: multiple violations reported" {
    var linter: Linter = .init(std.testing.allocator,
        \\const std = @import("std");
        \\fn bad(io: std.Io, comptime T: type, alloc: std.mem.Allocator) void {
        \\    _ = .{ io, T, alloc };
        \\}
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    var count: usize = 0;
    for (linter.diagnostics.items) |d| {
        if (d.rule == rules.Rule.Z023) count += 1;
    }
    try std.testing.expect(count >= 2);
}

test "Z023: comptime value after allocator is ok" {
    var linter: Linter = .init(std.testing.allocator,
        \\const std = @import("std");
        \\fn good(alloc: std.mem.Allocator, comptime size: usize) void {
        \\    _ = .{ alloc, size };
        \\}
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    for (linter.diagnostics.items) |d| {
        try std.testing.expect(d.rule != rules.Rule.Z023);
    }
}

test "Z023: comptime value before allocator is bad" {
    var linter: Linter = .init(std.testing.allocator,
        \\const std = @import("std");
        \\fn bad(comptime size: usize, alloc: std.mem.Allocator) void {
        \\    _ = .{ size, alloc };
        \\}
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    var found = false;
    for (linter.diagnostics.items) |d| {
        if (d.rule == rules.Rule.Z023) found = true;
    }
    try std.testing.expect(found);
}

test "Z023: comptime value before other is bad" {
    var linter: Linter = .init(std.testing.allocator,
        \\fn bad(value: u32, comptime size: usize) void {
        \\    _ = .{ value, size };
        \\}
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    var found = false;
    for (linter.diagnostics.items) |d| {
        if (d.rule == rules.Rule.Z023) found = true;
    }
    try std.testing.expect(found);
}

test "Z024: detect line exceeding 120 characters" {
    // Line with 121 characters (11 + 108 + 2)
    var linter: Linter = .init(std.testing.allocator, "const x = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\";\n", "test.zig", null);
    defer linter.deinit();
    linter.lint();
    var found = false;
    for (linter.diagnostics.items) |d| {
        if (d.rule == rules.Rule.Z024) found = true;
    }
    try std.testing.expect(found);
}

test "Z024: allow line with exactly 120 characters" {
    // Line with exactly 120 characters (11 + 107 + 2)
    var linter: Linter = .init(std.testing.allocator, "const x = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\";\n", "test.zig", null);
    defer linter.deinit();
    linter.lint();
    for (linter.diagnostics.items) |d| {
        if (d.rule == rules.Rule.Z024) {
            // Should not find Z024 for exactly 120 characters
            try std.testing.expect(false);
        }
    }
}

test "Z024: allow short line" {
    var linter: Linter = .init(std.testing.allocator, "const x = 1;\n", "test.zig", null);
    defer linter.deinit();
    linter.lint();
    for (linter.diagnostics.items) |d| {
        if (d.rule == rules.Rule.Z024) {
            try std.testing.expect(false);
        }
    }
}

test "Z025: detect catch return" {
    var linter: Linter = .init(std.testing.allocator,
        \\fn foo() !u32 {
        \\    return bar() catch |err| return err;
        \\}
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    var found = false;
    for (linter.diagnostics.items) |d| {
        if (d.rule == rules.Rule.Z025) found = true;
    }
    try std.testing.expect(found);
}

test "Z025: allow catch with different body" {
    var linter: Linter = .init(std.testing.allocator,
        \\fn foo() !u32 {
        \\    return bar() catch |err| {
        \\        log.err("{}", .{err});
        \\        return err;
        \\    };
        \\}
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    for (linter.diagnostics.items) |d| {
        if (d.rule == rules.Rule.Z025) {
            try std.testing.expect(false);
        }
    }
}

test "Z025: allow catch without payload" {
    var linter: Linter = .init(std.testing.allocator,
        \\fn foo() !u32 {
        \\    return bar() catch return;
        \\}
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    for (linter.diagnostics.items) |d| {
        if (d.rule == rules.Rule.Z025) {
            try std.testing.expect(false);
        }
    }
}

test "Z025: allow catch returning different value" {
    var linter: Linter = .init(std.testing.allocator,
        \\fn foo() !u32 {
        \\    return bar() catch |err| return error.Other;
        \\}
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    for (linter.diagnostics.items) |d| {
        if (d.rule == rules.Rule.Z025) {
            try std.testing.expect(false);
        }
    }
}

test "Z025: detect catch return in assignment context" {
    var linter: Linter = .init(std.testing.allocator,
        \\fn foo() !u32 {
        \\    const x = bar() catch |err| return err;
        \\    return x;
        \\}
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnosticCount(.Z025));
}

test "Z025: allow catch with discard payload" {
    var linter: Linter = .init(std.testing.allocator,
        \\fn foo() !u32 {
        \\    return bar() catch |_| return error.Other;
        \\}
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnosticCount(.Z025));
}

test "Z025: no false positive on clean code" {
    var linter: Linter = .init(std.testing.allocator,
        \\fn foo() !u32 {
        \\    return try bar();
        \\}
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnosticCount(.Z025));
}

test "Z026: detect empty catch block" {
    var linter: Linter = .init(std.testing.allocator,
        \\fn foo() void {
        \\    bar() catch {};
        \\}
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    var found = false;
    for (linter.diagnostics.items) |d| {
        if (d.rule == rules.Rule.Z026) found = true;
    }
    try std.testing.expect(found);
}

test "Z026: detect empty catch with payload" {
    var linter: Linter = .init(std.testing.allocator,
        \\fn foo() void {
        \\    bar() catch |_| {};
        \\}
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    var found = false;
    for (linter.diagnostics.items) |d| {
        if (d.rule == rules.Rule.Z026) found = true;
    }
    try std.testing.expect(found);
}

test "Z026: allow catch in defer" {
    var linter: Linter = .init(std.testing.allocator,
        \\fn foo() void {
        \\    defer writer.flush() catch {};
        \\}
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    for (linter.diagnostics.items) |d| {
        if (d.rule == rules.Rule.Z026) {
            try std.testing.expect(false);
        }
    }
}

test "Z026: allow catch in errdefer" {
    var linter: Linter = .init(std.testing.allocator,
        \\fn foo() void {
        \\    errdefer writer.flush() catch {};
        \\}
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    for (linter.diagnostics.items) |d| {
        if (d.rule == rules.Rule.Z026) {
            try std.testing.expect(false);
        }
    }
}

test "Z026: allow non-empty catch" {
    var linter: Linter = .init(std.testing.allocator,
        \\fn foo() void {
        \\    bar() catch |err| {
        \\        log.err("{}", .{err});
        \\    };
        \\}
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    for (linter.diagnostics.items) |d| {
        if (d.rule == rules.Rule.Z026) {
            try std.testing.expect(false);
        }
    }
}

test "Z026: allow catch with @panic" {
    var linter: Linter = .init(std.testing.allocator,
        \\fn foo() void {
        \\    bar() catch |err| {
        \\        @panic("unexpected");
        \\    };
        \\}
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnosticCount(.Z026));
}

test "Z026: allow catch with unreachable" {
    var linter: Linter = .init(std.testing.allocator,
        \\fn foo() void {
        \\    bar() catch |err| {
        \\        unreachable;
        \\    };
        \\}
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnosticCount(.Z026));
}

test "Z026: no false positive on clean code" {
    var linter: Linter = .init(std.testing.allocator,
        \\fn foo() void {
        \\    try bar();
        \\}
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnosticCount(.Z026));
}

test "Z026: detect multiple empty catches" {
    var linter: Linter = .init(std.testing.allocator,
        \\fn foo() void {
        \\    bar() catch {};
        \\    baz() catch {};
        \\}
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(2, linter.diagnosticCount(.Z026));
}

test "Z027: flag instance accessing const" {
    const ModuleGraph = @import("ModuleGraph.zig");
    const source =
        \\const Foo = struct {
        \\    field: u32,
        \\    const bar = 42;
        \\};
        \\const instance: Foo = .{ .field = 0 };
        \\pub fn main() void {
        \\    _ = instance.bar;
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

    var linter: Linter = .initWithSemantics(std.testing.allocator, source, path, &resolver, path, null);
    defer linter.deinit();

    linter.lint();

    var found = false;
    for (linter.diagnostics.items) |d| {
        if (d.rule == rules.Rule.Z027) {
            found = true;
            break;
        }
    }
    try std.testing.expect(found);
}

test "Z027: flag instance accessing static fn" {
    const ModuleGraph = @import("ModuleGraph.zig");
    const source =
        \\const Foo = struct {
        \\    field: u32,
        \\    fn staticFn() void {}
        \\};
        \\const instance: Foo = .{ .field = 0 };
        \\pub fn main() void {
        \\    instance.staticFn();
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

    var linter: Linter = .initWithSemantics(std.testing.allocator, source, path, &resolver, path, null);
    defer linter.deinit();

    linter.lint();

    var found = false;
    for (linter.diagnostics.items) |d| {
        if (d.rule == rules.Rule.Z027) {
            found = true;
            break;
        }
    }
    try std.testing.expect(found);
}

test "Z027: allow instance method call" {
    const ModuleGraph = @import("ModuleGraph.zig");
    const source =
        \\const Foo = struct {
        \\    field: u32,
        \\    fn getField(self: *@This()) u32 {
        \\        return self.field;
        \\    }
        \\};
        \\const instance: Foo = .{ .field = 0 };
        \\pub fn main() void {
        \\    _ = instance.getField();
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

    var linter: Linter = .initWithSemantics(std.testing.allocator, source, path, &resolver, path, null);
    defer linter.deinit();

    linter.lint();

    for (linter.diagnostics.items) |d| {
        if (d.rule == rules.Rule.Z027) {
            try std.testing.expect(false);
        }
    }
}

test "Z027: allow field access" {
    const ModuleGraph = @import("ModuleGraph.zig");
    const source =
        \\const Foo = struct {
        \\    field: u32,
        \\};
        \\const instance: Foo = .{ .field = 0 };
        \\pub fn main() void {
        \\    _ = instance.field;
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

    var linter: Linter = .initWithSemantics(std.testing.allocator, source, path, &resolver, path, null);
    defer linter.deinit();

    linter.lint();

    for (linter.diagnostics.items) |d| {
        if (d.rule == rules.Rule.Z027) {
            try std.testing.expect(false);
        }
    }
}

test "Z027: allow type-level access" {
    const ModuleGraph = @import("ModuleGraph.zig");
    const source =
        \\const Foo = struct {
        \\    field: u32,
        \\    const bar = 42;
        \\};
        \\pub fn main() void {
        \\    _ = Foo.bar;
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

    var linter: Linter = .initWithSemantics(std.testing.allocator, source, path, &resolver, path, null);
    defer linter.deinit();

    linter.lint();

    for (linter.diagnostics.items) |d| {
        if (d.rule == rules.Rule.Z027) {
            try std.testing.expect(false);
        }
    }
}

test "Z027: no warning without semantic context" {
    var linter: Linter = .init(std.testing.allocator,
        \\const Foo = struct {
        \\    const bar = 42;
        \\};
        \\const instance: Foo = .{};
        \\pub fn main() void {
        \\    _ = instance.bar;
        \\}
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    for (linter.diagnostics.items) |d| {
        if (d.rule == rules.Rule.Z027) {
            try std.testing.expect(false);
        }
    }
}

test "Z027: allow method with Self receiver" {
    const ModuleGraph = @import("ModuleGraph.zig");
    const source =
        \\const Foo = struct {
        \\    const Self = @This();
        \\    field: u32,
        \\    fn getField(self: *Self) u32 {
        \\        return self.field;
        \\    }
        \\};
        \\const instance: Foo = .{ .field = 0 };
        \\pub fn main() void {
        \\    _ = instance.getField();
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

    var linter: Linter = .initWithSemantics(std.testing.allocator, source, path, &resolver, path, null);
    defer linter.deinit();

    linter.lint();

    for (linter.diagnostics.items) |d| {
        if (d.rule == rules.Rule.Z027) {
            try std.testing.expect(false);
        }
    }
}

test "Z027: allow method with named type receiver" {
    const ModuleGraph = @import("ModuleGraph.zig");
    const source =
        \\const Foo = struct {
        \\    field: u32,
        \\    fn getField(self: *Foo) u32 {
        \\        return self.field;
        \\    }
        \\};
        \\const instance: Foo = .{ .field = 0 };
        \\pub fn main() void {
        \\    _ = instance.getField();
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

    var linter: Linter = .initWithSemantics(std.testing.allocator, source, path, &resolver, path, null);
    defer linter.deinit();

    linter.lint();

    for (linter.diagnostics.items) |d| {
        if (d.rule == rules.Rule.Z027) {
            try std.testing.expect(false);
        }
    }
}

test "Z029: detect redundant @as in call arg" {
    var linter: Linter = .init(std.testing.allocator,
        \\fn foo(x: u32) void {
        \\    _ = x;
        \\}
        \\pub fn main() void {
        \\    foo(@as(u32, 1));
        \\}
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnosticCount(.Z029));
}

test "Z029: allow @as with different type in call arg" {
    var linter: Linter = .init(std.testing.allocator,
        \\fn foo(x: u32) void {
        \\    _ = x;
        \\}
        \\pub fn main() void {
        \\    foo(@as(u16, 1));
        \\}
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnosticCount(.Z029));
}

test "Z029: detect redundant @as in array init" {
    var linter: Linter = .init(std.testing.allocator,
        \\pub fn main() void {
        \\    const xs = [_]u32{@as(u32, 1)};
        \\    _ = xs;
        \\}
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnosticCount(.Z029));
}

test "Z029: allow @as with different type in array init" {
    var linter: Linter = .init(std.testing.allocator,
        \\pub fn main() void {
        \\    const xs = [_]u32{@as(u16, 1)};
        \\    _ = xs;
        \\}
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnosticCount(.Z029));
}

test "Z029: detect redundant @as in method call arg" {
    const ModuleGraph = @import("ModuleGraph.zig");
    const source =
        \\const MyType = struct {
        \\    value: u32,
        \\    pub fn setValue(self: *@This(), v: u32) void {
        \\        self.value = v;
        \\    }
        \\};
        \\const instance: MyType = .{ .value = 0 };
        \\pub fn main() void {
        \\    instance.setValue(@as(u32, 42));
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

    var linter: Linter = .initWithSemantics(std.testing.allocator, source, path, &resolver, path, null);
    defer linter.deinit();

    linter.lint();

    try std.testing.expectEqual(1, linter.diagnosticCount(.Z029));
}

test "Z029: multiple args with redundant @as" {
    var linter: Linter = .init(std.testing.allocator,
        \\fn bar(a: u32, b: u32) void {
        \\    _ = a;
        \\    _ = b;
        \\}
        \\pub fn main() void {
        \\    bar(@as(u32, 1), @as(u32, 2));
        \\}
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(2, linter.diagnosticCount(.Z029));
}

test "Z029: detect redundant @as in struct field init" {
    var linter: Linter = .init(std.testing.allocator,
        \\const Foo = struct {
        \\    x: u32,
        \\    y: u32,
        \\};
        \\pub fn main() void {
        \\    const f: Foo = .{ .x = @as(u32, 1), .y = 2 };
        \\    _ = f;
        \\}
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnosticCount(.Z029));
}

test "Z029: allow @as with different type in struct field init" {
    var linter: Linter = .init(std.testing.allocator,
        \\const Foo = struct {
        \\    x: u32,
        \\};
        \\pub fn main() void {
        \\    const f: Foo = .{ .x = @as(u16, 1) };
        \\    _ = f;
        \\}
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnosticCount(.Z029));
}

test "Z029: detect redundant @as in explicit struct init" {
    var linter: Linter = .init(std.testing.allocator,
        \\const Foo = struct {
        \\    x: u32,
        \\};
        \\pub fn main() void {
        \\    const f = Foo{ .x = @as(u32, 1) };
        \\    _ = f;
        \\}
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnosticCount(.Z029));
}

test "Z029: no false positive on clean call args" {
    var linter: Linter = .init(std.testing.allocator,
        \\fn foo(x: u32) void {
        \\    _ = x;
        \\}
        \\pub fn main() void {
        \\    foo(42);
        \\}
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnosticCount(.Z029));
}

test "Z029: skip unresolvable function call" {
    var linter: Linter = .init(std.testing.allocator,
        \\pub fn main() void {
        \\    unknown_fn(@as(u32, 1));
        \\}
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnosticCount(.Z029));
}

test "Z029: skip call with anytype param" {
    var linter: Linter = .init(std.testing.allocator,
        \\fn foo(x: anytype) void {
        \\    _ = x;
        \\}
        \\pub fn main() void {
        \\    foo(@as(u32, 1));
        \\}
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnosticCount(.Z029));
}

test "Z029: detect multiple redundant @as in array init" {
    var linter: Linter = .init(std.testing.allocator,
        \\pub fn main() void {
        \\    const xs = [_]u32{ @as(u32, 1), @as(u32, 2), 3 };
        \\    _ = xs;
        \\}
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(2, linter.diagnosticCount(.Z029));
}

test "Z029: skip array init without type annotation" {
    var linter: Linter = .init(std.testing.allocator,
        \\pub fn main() void {
        \\    const xs = .{ @as(u32, 1), @as(u32, 2) };
        \\    _ = xs;
        \\}
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnosticCount(.Z029));
}

test "Z029: detect in sized array init" {
    var linter: Linter = .init(std.testing.allocator,
        \\pub fn main() void {
        \\    const xs = [2]u32{ @as(u32, 1), @as(u32, 2) };
        \\    _ = xs;
        \\}
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(2, linter.diagnosticCount(.Z029));
}

test "Z029: skip struct init without known type" {
    var linter: Linter = .init(std.testing.allocator,
        \\pub fn main() void {
        \\    const f = .{ .x = @as(u32, 1) };
        \\    _ = f;
        \\}
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnosticCount(.Z029));
}

test "Z029: detect multiple redundant @as in struct fields" {
    var linter: Linter = .init(std.testing.allocator,
        \\const Foo = struct {
        \\    x: u32,
        \\    y: u32,
        \\};
        \\pub fn main() void {
        \\    const f: Foo = .{ .x = @as(u32, 1), .y = @as(u32, 2) };
        \\    _ = f;
        \\}
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(2, linter.diagnosticCount(.Z029));
}

test "Z029: skip struct field with unknown type in container" {
    var linter: Linter = .init(std.testing.allocator,
        \\pub fn main() void {
        \\    const f: UnknownType = .{ .x = @as(u32, 1) };
        \\    _ = f;
        \\}
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnosticCount(.Z029));
}

test "Z029: mixed match and mismatch in call args" {
    var linter: Linter = .init(std.testing.allocator,
        \\fn foo(a: u32, b: u16) void {
        \\    _ = a;
        \\    _ = b;
        \\}
        \\pub fn main() void {
        \\    foo(@as(u32, 1), @as(u32, 2));
        \\}
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnosticCount(.Z029));
}

test "Z028: inline import in switch" {
    var linter: Linter = .init(std.testing.allocator,
        \\const builtin = @import("builtin");
        \\const Backend = switch (builtin.os.tag) {
        \\    .linux => @import("linux.zig"),
        \\    .macos => @import("macos.zig"),
        \\    else => @compileError("unsupported"),
        \\};
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(2, linter.diagnosticCount(.Z028));
}

test "Z028: inline import in function call" {
    var linter: Linter = .init(std.testing.allocator,
        \\fn foo(x: anytype) void {
        \\    _ = x;
        \\}
        \\pub fn main() void {
        \\    foo(@import("bar.zig").baz);
        \\}
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnosticCount(.Z028));
}

test "Z028: allow top-level const import" {
    var linter: Linter = .init(std.testing.allocator,
        \\const std = @import("std");
        \\const other = @import("other.zig");
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnosticCount(.Z028));
}

test "Z028: disallow import inside function" {
    var linter: Linter = .init(std.testing.allocator,
        \\pub fn main() void {
        \\    const std = @import("std");
        \\    _ = std;
        \\}
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnosticCount(.Z028));
}

test "Z028: allow discard import for pulling in tests" {
    var linter: Linter = .init(std.testing.allocator,
        \\test {
        \\    _ = @import("other.zig");
        \\}
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnosticCount(.Z028));
}

test "Z028: allow const import in test block" {
    var linter: Linter = .init(std.testing.allocator,
        \\test "example" {
        \\    const testing = @import("testing.zig");
        \\    testing.check();
        \\}
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnosticCount(.Z028));
}

test "Z028: allow field access on import" {
    var linter: Linter = .init(std.testing.allocator,
        \\const Rule = @import("rules.zig").Rule;
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnosticCount(.Z028));
}

test "Z030: detect missing self.* = undefined in deinit" {
    var linter: Linter = .init(std.testing.allocator,
        \\const Foo = struct {
        \\    a: u32,
        \\    fn deinit(self: *Foo) void {
        \\        _ = self;
        \\    }
        \\};
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnosticCount(.Z030));
}

test "Z030: allow deinit with self.* = undefined at end" {
    var linter: Linter = .init(std.testing.allocator,
        \\const Foo = struct {
        \\    a: u32,
        \\    fn deinit(self: *Foo) void {
        \\        self.a = 0;
        \\        self.* = undefined;
        \\    }
        \\};
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnosticCount(.Z030));
}

test "Z030: allow deinit with defer self.* = undefined" {
    var linter: Linter = .init(std.testing.allocator,
        \\const Foo = struct {
        \\    a: u32,
        \\    fn deinit(self: *Foo) void {
        \\        defer self.* = undefined;
        \\        cleanup();
        \\    }
        \\};
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnosticCount(.Z030));
}

test "Z030: detect early return without defer" {
    var linter: Linter = .init(std.testing.allocator,
        \\const Foo = struct {
        \\    a: u32,
        \\    fn deinit(self: *Foo) void {
        \\        if (self.a == 0) return;
        \\        self.* = undefined;
        \\    }
        \\};
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnosticCount(.Z030));
}

test "Z030: allow early return with defer" {
    var linter: Linter = .init(std.testing.allocator,
        \\const Foo = struct {
        \\    a: u32,
        \\    fn deinit(self: *Foo) void {
        \\        defer self.* = undefined;
        \\        if (self.a == 0) return;
        \\        cleanup();
        \\    }
        \\};
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnosticCount(.Z030));
}

test "Z030: skip non-pointer receiver deinit" {
    var linter: Linter = .init(std.testing.allocator,
        \\const Foo = struct {
        \\    a: u32,
        \\    fn deinit(self: Foo) void {
        \\        _ = self;
        \\    }
        \\};
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnosticCount(.Z030));
}

test "Z030: skip non-deinit functions" {
    var linter: Linter = .init(std.testing.allocator,
        \\const Foo = struct {
        \\    a: u32,
        \\    fn close(self: *Foo) void {
        \\        _ = self;
        \\    }
        \\};
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnosticCount(.Z030));
}

test "Z030: handle different self parameter names" {
    var linter: Linter = .init(std.testing.allocator,
        \\const Foo = struct {
        \\    a: u32,
        \\    fn deinit(s: *Foo) void {
        \\        s.* = undefined;
        \\    }
        \\};
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnosticCount(.Z030));
}

test "Z031: detect underscore prefix in function" {
    var linter: Linter = .init(std.testing.allocator, "fn _privateFunc() void {}", "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnosticCount(.Z031));
}

test "Z031: detect underscore prefix in variable" {
    var linter: Linter = .init(std.testing.allocator, "const _privateVar: u32 = undefined;", "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnosticCount(.Z031));
}

test "Z031: allow single underscore discard" {
    var linter: Linter = .init(std.testing.allocator, "const _ = 42;", "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnosticCount(.Z031));
}

test "Z031: allow double underscore prefix" {
    var linter: Linter = .init(std.testing.allocator, "const __builtin = 42;", "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnosticCount(.Z031));
}

test "Z031: allow normal names" {
    var linter: Linter = .init(std.testing.allocator, "fn myFunc() void {}", "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnosticCount(.Z031));
}

test "Z032: detect XMLParser" {
    var linter: Linter = .init(std.testing.allocator, "const XMLParser = struct {};", "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnosticCount(.Z032));
}

test "Z032: detect HTTPSConnection" {
    var linter: Linter = .init(std.testing.allocator, "const HTTPSConnection = struct {};", "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnosticCount(.Z032));
}

test "Z032: detect function with acronym" {
    var linter: Linter = .init(std.testing.allocator, "fn parseXML() void {}", "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnosticCount(.Z032));
}

test "Z032: allow XmlParser" {
    var linter: Linter = .init(std.testing.allocator, "const XmlParser = struct {};", "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnosticCount(.Z032));
}

test "Z032: allow two-letter at start" {
    var linter: Linter = .init(std.testing.allocator, "const IoError = struct {};", "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnosticCount(.Z032));
}

test "Z032: detect IOError" {
    var linter: Linter = .init(std.testing.allocator, "const IOError = struct {};", "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnosticCount(.Z032));
}

test "Z033: disabled by default" {
    var linter: Linter = .init(std.testing.allocator, "const DataManager = struct {};", "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnosticCount(.Z033));
}

test "Z033: detect Data when enabled" {
    const config: Config = .{ .rules = .{ .Z033 = .{ .enabled = true } } };
    var linter: Linter = .init(std.testing.allocator, "const UserData = struct {};", "test.zig", &config);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnosticCount(.Z033));
}

test "Z033: detect Manager when enabled" {
    const config: Config = .{ .rules = .{ .Z033 = .{ .enabled = true } } };
    var linter: Linter = .init(std.testing.allocator, "const StateManager = struct {};", "test.zig", &config);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnosticCount(.Z033));
}

test "Z033: detect Context when enabled" {
    const config: Config = .{ .rules = .{ .Z033 = .{ .enabled = true } } };
    var linter: Linter = .init(std.testing.allocator, "const AppContext = struct {};", "test.zig", &config);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnosticCount(.Z033));
}

test "Z033: detect utils when enabled" {
    const config: Config = .{ .rules = .{ .Z033 = .{ .enabled = true } } };
    var linter: Linter = .init(std.testing.allocator, "fn stringUtils() void {}", "test.zig", &config);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnosticCount(.Z033));
}

test "Z033: allow normal names when enabled" {
    const config: Config = .{ .rules = .{ .Z033 = .{ .enabled = true } } };
    var linter: Linter = .init(std.testing.allocator, "const Parser = struct {};", "test.zig", &config);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnosticCount(.Z033));
}
