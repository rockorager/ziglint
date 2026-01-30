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
- `--ignore <rule>` - Ignore a rule (e.g., `Z001`). Can be repeated.
- `-h, --help` - Show help message

## Rules

| Code | Description |
|------|-------------|
| Z001 | Function names should be camelCase |
| Z002 | Unused variable that has a value |
| Z003 | Parse error |
| Z004 | Prefer `const x: T = .{}` over `const x = T{}` |
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
| Z017 | Redundant `try` in return: `return try expr` → `return expr` |
| Z018 | Redundant `@as` when type is already known from context |
| Z019 | `@This()` in named struct; use the type name instead |
| Z020 | Inline `@This()`; assign to a constant first |
| Z021 | File-struct `@This()` alias should match filename |
| Z022 | `@This()` alias in anonymous/local struct should be `Self` |
| Z023 | Parameter order: comptime before runtime, pointers before values |
| Z024 | Line exceeds maximum length (default: 120) |
| Z025 | Redundant `catch |err| return err`; use `try` instead |
| Z026 | Empty `catch` block suppresses errors |
| Z027 | Access declaration through type instead of instance |
| Z029 | Redundant `@as` cast; type already known from context |

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
