# ziglint

A linter for Zig source code.

## Usage

```
ziglint [options] [paths...]
```

When run without arguments, ziglint looks for a `.ziglint.zon` config file and uses the paths specified there, or defaults to the current directory.

Directories are scanned recursively for `.zig` files.

### Options

- `--zig-lib-path <path>` - Override the path to the Zig standard library (auto-detected from `zig env` if not specified)
- `--only <rule>` - Lint only the specified rule (e.g., `Z001`). Can be repeated.
- `--ignore <rule>` - Ignore a rule (e.g., `Z001`). Can be repeated.
- `-h, --help` - Show help message

## Rules

| Code | Description |
|------|-------------|
| Z001 | Function names should be camelCase |
| Z002 | Avoid initialized variables that look like named discards |
| Z003 | Parse error with parser explanation |
| Z004 | Prefer type annotations with anonymous struct initializers |
| Z005 | Type function names should be PascalCase |
| Z006 | Variable names should be snake_case |
| Z007 | Duplicate import |
| Z009 | Files with top-level fields should be PascalCase |
| Z010 | Redundant type specifier; prefer `.value` over explicit type |
| Z011 | Deprecated method call |
| Z012 | Public function exposes private type |
| Z013 | Unused import |
| Z014 | Error set names should be PascalCase |
| Z015 | Public function exposes private error set |
| Z016 | Split compound assert: `assert(a and b)` → `assert(a); assert(b);` |
| Z017 | Avoid `try` directly in return expressions |
| Z018 | Redundant `@as` when type is already known from context |
| Z019 | `@This()` in named struct; use the type name instead |
| Z020 | Inline `@This()`; use the named type or a `Self` alias |
| Z021 | File-struct `@This()` alias should match filename or be `Self` |
| Z022 | `@This()` alias in anonymous/local struct should be `Self` |
| Z023 | Parameter order: `comptime T: type`, comptime values, `Allocator`, `Io`; runtime values position-free |
| Z024 | Line exceeds maximum byte length (default: 120) |
| Z025 | Redundant `catch |err| return err`; use `try` instead |
| Z026 | Empty `catch` block suppresses errors |
| Z027 | Access declaration through type instead of instance |
| Z028 | Inline `@import`; assign to a top-level `const` |
| Z029 | Redundant `@as` cast; type already known from context |
| Z030 | `deinit` should set `self.* = undefined` |
| Z031 | Avoid underscore prefix in identifiers |
| Z032 | Acronyms should use standard casing |
| Z033 | Avoid redundant words in type names (disabled by default) |

## Configuration

Create a `.ziglint.zon` file in your project root to configure ziglint:

```zig
.{
    // Paths to lint (default: current directory)
    .paths = .{
        "src",
        "build.zig",
    },

    // Per-rule configuration
    .rules = .{
        // Disable a rule entirely
        .Z001 = .{ .enabled = false },

        // Configure rule-specific settings
        .Z024 = .{ .max_length = 80 },
    },
}
```

### Inline Ignores

You can ignore specific rules on a per-line basis using comments:

```zig
fn MyBadName() void {} // ziglint-ignore: Z001

// ziglint-ignore: Z001
fn AnotherBadName() void {}
```
