//! Module graph for semantic analysis.
//!
//! Parses @import calls from AST and recursively resolves all reachable modules,
//! building a graph that maps import paths to parsed ASTs and ZIR.

const std = @import("std");
const Ast = std.zig.Ast;
const Zir = std.zig.Zir;
const AstGen = std.zig.AstGen;

const ModuleGraph = @This();

allocator: std.mem.Allocator,
zig_lib_path: ?[]const u8,
root_dir: []const u8,
modules: std.StringHashMapUnmanaged(Module),

pub const Module = struct {
    path: []const u8,
    source: [:0]const u8,
    tree: Ast,
    zir: ?Zir = null,
};

pub fn init(allocator: std.mem.Allocator, root_source: []const u8, zig_lib_path: ?[]const u8) !ModuleGraph {
    const root_dir = std.fs.path.dirname(root_source) orelse ".";

    var graph: ModuleGraph = .{
        .allocator = allocator,
        .zig_lib_path = zig_lib_path,
        .root_dir = root_dir,
        .modules = .empty,
    };

    try graph.addModule(root_source);
    return graph;
}

pub fn deinit(self: *ModuleGraph) void {
    var iter = self.modules.valueIterator();
    while (iter.next()) |mod| {
        if (mod.zir) |*zir| zir.deinit(self.allocator);
        mod.tree.deinit(self.allocator);
        self.allocator.free(mod.source);
        self.allocator.free(mod.path);
    }
    self.modules.deinit(self.allocator);
}

fn addModule(self: *ModuleGraph, path: []const u8) !void {
    const canonical = try std.fs.cwd().realpathAlloc(self.allocator, path);

    if (self.modules.contains(canonical)) {
        self.allocator.free(canonical);
        return;
    }

    const source = std.fs.cwd().readFileAllocOptions(
        self.allocator,
        canonical,
        1024 * 1024 * 16,
        null,
        .@"1",
        0,
    ) catch |err| {
        std.log.warn("cannot read '{s}': {}", .{ canonical, err });
        self.allocator.free(canonical);
        return;
    };

    const tree = Ast.parse(self.allocator, source, .zig) catch {
        self.allocator.free(source);
        self.allocator.free(canonical);
        return;
    };

    const zir: ?Zir = if (tree.errors.len == 0)
        AstGen.generate(self.allocator, tree) catch |err| blk: {
            std.log.warn("ZIR generation failed for '{s}': {}", .{ canonical, err });
            break :blk null;
        }
    else
        null;

    try self.modules.put(self.allocator, canonical, .{
        .path = canonical,
        .source = source,
        .tree = tree,
        .zir = zir,
    });

    // Recursively add imported modules
    const imports = try self.extractImports(&tree, canonical);
    defer self.allocator.free(imports);

    for (imports) |import_path| {
        defer self.allocator.free(import_path);
        self.addModule(import_path) catch continue;
    }
}

fn extractImports(self: *ModuleGraph, tree: *const Ast, module_path: []const u8) ![][]const u8 {
    var imports: std.ArrayListUnmanaged([]const u8) = .empty;
    errdefer {
        for (imports.items) |p| self.allocator.free(p);
        imports.deinit(self.allocator);
    }

    for (tree.rootDecls()) |node| {
        try self.collectImportsFromNode(tree, node, module_path, &imports);
    }

    return imports.toOwnedSlice(self.allocator);
}

fn collectImportsFromNode(
    self: *ModuleGraph,
    tree: *const Ast,
    node: Ast.Node.Index,
    module_path: []const u8,
    imports: *std.ArrayListUnmanaged([]const u8),
) !void {
    const tag = tree.nodeTag(node);

    switch (tag) {
        .simple_var_decl, .aligned_var_decl, .local_var_decl, .global_var_decl => {
            const var_decl = tree.fullVarDecl(node) orelse return;
            const init_node = var_decl.ast.init_node.unwrap() orelse return;
            try self.checkForImport(tree, init_node, module_path, imports);
        },
        .fn_decl => {
            const data = tree.nodeData(node).node_and_node;
            try self.collectImportsFromNode(tree, data[0], module_path, imports);
            try self.collectImportsFromNode(tree, data[1], module_path, imports);
        },
        .block, .block_semicolon => {
            var buf: [2]Ast.Node.Index = undefined;
            const stmts = tree.blockStatements(&buf, node) orelse return;
            for (stmts) |stmt| try self.collectImportsFromNode(tree, stmt, module_path, imports);
        },
        .block_two, .block_two_semicolon => {
            const data = tree.nodeData(node).opt_node_and_opt_node;
            if (data[0].unwrap()) |n| try self.collectImportsFromNode(tree, n, module_path, imports);
            if (data[1].unwrap()) |n| try self.collectImportsFromNode(tree, n, module_path, imports);
        },
        else => {},
    }
}

fn checkForImport(
    self: *ModuleGraph,
    tree: *const Ast,
    node: Ast.Node.Index,
    module_path: []const u8,
    imports: *std.ArrayListUnmanaged([]const u8),
) !void {
    const tag = tree.nodeTag(node);
    if (tag != .builtin_call_two and tag != .builtin_call_two_comma and
        tag != .builtin_call and tag != .builtin_call_comma)
    {
        return;
    }

    const main_token = tree.nodeMainToken(node);
    const builtin_name = tree.tokenSlice(main_token);
    if (!std.mem.eql(u8, builtin_name, "@import")) return;

    var buf: [2]Ast.Node.Index = undefined;
    const params = tree.builtinCallParams(&buf, node) orelse return;
    if (params.len == 0) return;

    const arg_token = tree.nodeMainToken(params[0]);
    const raw_path = tree.tokenSlice(arg_token);

    // Strip quotes from string literal
    if (raw_path.len < 2 or raw_path[0] != '"') return;
    const import_str = raw_path[1 .. raw_path.len - 1];

    const resolved = try self.resolveImportPath(import_str, module_path);
    if (resolved) |path| {
        try imports.append(self.allocator, path);
    }
}

fn resolveImportPath(self: *ModuleGraph, import_str: []const u8, module_path: []const u8) !?[]const u8 {
    // Handle "std" import
    if (std.mem.eql(u8, import_str, "std")) {
        const lib_path = self.zig_lib_path orelse return null;
        return try std.fs.path.join(self.allocator, &.{ lib_path, "std", "std.zig" });
    }

    // Handle builtin (skip it)
    if (std.mem.eql(u8, import_str, "builtin")) {
        return null;
    }

    // Handle relative .zig imports
    if (std.mem.endsWith(u8, import_str, ".zig")) {
        const module_dir = std.fs.path.dirname(module_path) orelse ".";
        return try std.fs.path.join(self.allocator, &.{ module_dir, import_str });
    }

    return null;
}

pub fn moduleCount(self: *const ModuleGraph) usize {
    return self.modules.count();
}

pub fn getModule(self: *const ModuleGraph, path: []const u8) ?*const Module {
    const canonical = std.fs.cwd().realpathAlloc(self.allocator, path) catch return null;
    defer self.allocator.free(canonical);
    return self.modules.getPtr(canonical);
}

pub fn zirCount(self: *const ModuleGraph) usize {
    var count: usize = 0;
    var iter = self.modules.valueIterator();
    while (iter.next()) |mod| {
        if (mod.zir != null) count += 1;
    }
    return count;
}

test "parse simple module" {
    const source =
        \\const std = @import("std");
        \\pub fn main() void {}
    ;

    // Write temp file
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    try tmp_dir.dir.writeFile(.{ .sub_path = "main.zig", .data = source });

    const path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, "main.zig");
    defer std.testing.allocator.free(path);

    var graph = try ModuleGraph.init(std.testing.allocator, path, null);
    defer graph.deinit();

    try std.testing.expectEqual(1, graph.moduleCount());
}

test "resolve relative import" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    try tmp_dir.dir.writeFile(.{ .sub_path = "main.zig", .data = "const utils = @import(\"utils.zig\");" });
    try tmp_dir.dir.writeFile(.{ .sub_path = "utils.zig", .data = "pub fn helper() void {}" });

    const path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, "main.zig");
    defer std.testing.allocator.free(path);

    var graph = try ModuleGraph.init(std.testing.allocator, path, null);
    defer graph.deinit();

    try std.testing.expectEqual(2, graph.moduleCount());
}

test "handle missing import gracefully" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    try tmp_dir.dir.writeFile(.{ .sub_path = "main.zig", .data = "const missing = @import(\"nonexistent.zig\");" });

    const path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, "main.zig");
    defer std.testing.allocator.free(path);

    var graph = try ModuleGraph.init(std.testing.allocator, path, null);
    defer graph.deinit();

    try std.testing.expectEqual(1, graph.moduleCount());
}

test "no duplicate modules" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    try tmp_dir.dir.writeFile(.{ .sub_path = "main.zig", .data = 
        \\const a = @import("shared.zig");
        \\const b = @import("other.zig");
    });
    try tmp_dir.dir.writeFile(.{ .sub_path = "other.zig", .data = "const shared = @import(\"shared.zig\");" });
    try tmp_dir.dir.writeFile(.{ .sub_path = "shared.zig", .data = "pub const x = 1;" });

    const path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, "main.zig");
    defer std.testing.allocator.free(path);

    var graph = try ModuleGraph.init(std.testing.allocator, path, null);
    defer graph.deinit();

    // main.zig, other.zig, shared.zig - no duplicates
    try std.testing.expectEqual(3, graph.moduleCount());
}

test "generate ZIR for valid modules" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    try tmp_dir.dir.writeFile(.{ .sub_path = "main.zig", .data = "pub fn main() void {}" });

    const path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, "main.zig");
    defer std.testing.allocator.free(path);

    var graph = try ModuleGraph.init(std.testing.allocator, path, null);
    defer graph.deinit();

    try std.testing.expectEqual(1, graph.moduleCount());
    try std.testing.expectEqual(1, graph.zirCount());

    const mod = graph.getModule(path);
    try std.testing.expect(mod != null);
    try std.testing.expect(mod.?.zir != null);
}

test "skip ZIR for modules with parse errors" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    try tmp_dir.dir.writeFile(.{ .sub_path = "main.zig", .data = "fn broken( {}" });

    const path = try tmp_dir.dir.realpathAlloc(std.testing.allocator, "main.zig");
    defer std.testing.allocator.free(path);

    var graph = try ModuleGraph.init(std.testing.allocator, path, null);
    defer graph.deinit();

    try std.testing.expectEqual(1, graph.moduleCount());
    try std.testing.expectEqual(0, graph.zirCount());
}
