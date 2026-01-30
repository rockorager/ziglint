---
name: new-rule
description: Add a new linter rule to ziglint. Use when creating a new Z-rule, implementing a lint check, or adding code analysis.
---

# Adding a New Linter Rule

When adding a new rule, you MUST modify these files in order:

## 1. Determine the Rule Number

Check `src/rules.zig` to find the next available rule number. Rules use the format `ZXXX` (e.g., Z001, Z025).

## 2. Add Rule Definition (`src/rules.zig`)

### Add enum variant
In the `Rule` enum, add the new rule in numerical order:
```zig
pub const Rule = enum(u16) {
    // ... existing rules
    ZXXX = XXX,  // Add your rule here
};
```

### Add config type (if rule has parameters)
If the rule needs configuration beyond just `enabled`, add a case in `ConfigType()`:
```zig
fn ConfigType(comptime self: Rule) type {
    return switch (self) {
        .ZXXX => RuleConfig(true, struct { my_param: u32 = 100 }),
        // ...
    };
}
```

### Add error message
In `writeMessage()`, add the message formatting. Use ANSI colors via the provided variables (`y` for yellow, `r` for reset):
```zig
.ZXXX => try writer.print("description with {s}'{s}'{s} highlighted", .{ y, context, r }),
```

## 3. Implement the Check (`src/Linter.zig`)

### Add check function
Create a function following the naming pattern `checkXxx`:
```zig
fn checkMyRule(self: *Linter, node: Ast.Node.Index) void {
    // Skip if rule is disabled
    if (!self.ruleEnabled(.ZXXX)) return;

    // Get node data from AST
    const tag = self.tree.nodeTag(node);
    // ... your logic

    // Report violation
    const loc = self.tree.tokenLocation(0, token);
    self.report(loc, .ZXXX, context_string);
}
```

### Call from visitor
Add your check to the appropriate place:

**For per-node checks**, add to `visitNode()` switch:
```zig
.fn_decl => self.checkFnDecl(node),
.my_node_type => self.checkMyRule(node),  // Add here
```

**For whole-file checks**, call from `lint()` directly:
```zig
pub fn lint(self: *Linter) void {
    // ... existing checks
    self.checkMyWholeFileRule();  // Add here
}
```

## 4. Add Tests (`src/Linter.zig`)

Add tests at the bottom of the file following this pattern:
```zig
test "ZXXX: detect violation case" {
    var linter: Linter = .init(std.testing.allocator,
        \\const x = bad_code;
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(1, linter.diagnosticCount(.ZXXX));
}

test "ZXXX: allow valid case" {
    var linter: Linter = .init(std.testing.allocator,
        \\const x = good_code;
    , "test.zig", null);
    defer linter.deinit();
    linter.lint();
    try std.testing.expectEqual(0, linter.diagnosticCount(.ZXXX));
}
```

## 5. Update Documentation

**IMPORTANT: Do not skip these steps!**

### Add to README.md

Add the rule to the rules table in README.md, maintaining numerical order:
```markdown
| ZXXX | Brief description of what the rule checks |
```

### Create Rule Documentation (`docs/rules/ZXXX.md`)

Create a detailed documentation file with executable examples:

```markdown
---
rule: ZXXX
title: Brief description of the rule
enabled: true
---

# ZXXX: Brief description

Explanation of what this rule checks and why it matters.

## Examples

### Bad

\`\`\`zig
// expect: ZXXX
code_that_triggers_the_rule();
\`\`\`

### Good

\`\`\`zig
code_that_passes();
\`\`\`

## Configuration

(Include this section if the rule has configurable parameters)

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `max_length` | `u32` | `120` | Maximum allowed line length |

Example `.ziglint.zon`:
\`\`\`zig
.rules = .{
    .ZXXX = .{ .max_length = 80 },
},
\`\`\`

## Rationale

Why this rule exists and what problems it prevents.
```

**Key points:**
- Code blocks with `// expect: ZXXX` comments are tested to trigger the rule
- Code blocks without expect comments are tested to produce no warnings
- These examples are validated by `zig build test` - if the rule changes and examples become inaccurate, the build fails
- Include both bad (triggering) and good (passing) examples

## 6. Run Tests

```bash
zig build test
```

## Common Patterns

### Helper functions available in Linter.zig:
- `isValidFunctionName(name)` - Check camelCase
- `isPascalCase(name)` - Check PascalCase
- `isSnakeCase(name)` - Check snake_case
- `isTypeExpression(node)` - Check if node is a type
- `isBuiltinType(name)` - Check if name is a builtin type

### AST access:
- `self.tree.nodeTag(node)` - Get node type
- `self.tree.tokenSlice(token_idx)` - Get token text
- `self.tree.tokenLocation(0, token_idx)` - Get line/column
- `self.tree.fullVarDecl(node)` - Parse variable declaration
- `self.tree.fullFnProto(&buf, node)` - Parse function prototype

### Encoded context (for multi-part messages):
```zig
// Use null byte as separator
const context = alloc.alloc(u8, part1.len + 1 + part2.len);
@memcpy(context[0..part1.len], part1);
context[part1.len] = 0;
@memcpy(context[part1.len + 1..], part2);
```
