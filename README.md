# ziglint

A linter for Zig source code.

## Usage

```
ziglint [options] <paths...>
```

Directories are scanned recursively for `.zig` files.

### Options

- `--zig-lib-path <path>` - Override the path to the Zig standard library (auto-detected from `zig env` if not specified)
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
