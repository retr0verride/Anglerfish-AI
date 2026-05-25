# Substage audit — apply at every substage commit

Before committing any slice, perform a full audit pass. Do not change
behaviour or add features.

## Cleanup

### Code hygiene
- Remove dead code, unused imports, unreachable branches
- Tighten type annotations that are broader than needed
- Replace any `# type: ignore` that can be resolved cleanly
- Ensure all public functions have docstrings consistent with existing codebase style

### Test hygiene
- Remove duplicate or redundant test cases
- Ensure test names accurately describe what they assert
- Remove any `# noqa` or `# pragma: no cover` that are no longer needed

### Doc hygiene
- Update inline comments that no longer match the code
- If this slice changes a module's public interface, check ARCHITECTURE.md and API_REFERENCE.md for references that need updating

## Hallucination check

### Invented interfaces
- Every import must resolve to a real module in this codebase or a declared dependency in pyproject.toml
- Every method or attribute call must exist on the actual type -- verify against source, not assumption
- No invented config keys, env vars, or Pydantic fields that aren't declared in `config/models.py`

### Invented behaviour
- Any claim that a function "already handles" an edge case must be verified against the actual implementation
- No placeholder logic that assumes a future stage has shipped (e.g. calling `intent.extract()` when Stage 5 is not started)
- Stubs for future stages must be explicitly marked with `# Stage N` comments and return safe defaults

### Test validity
- Tests must assert real behaviour, not mock everything and assert the mock was called
- No test that passes regardless of the implementation under test
- Coverage must reflect genuine execution paths, not lines hit by vacuous assertions

## No slop

### Remove slop
- No filler comments that restate what the code does (`# increment counter`, `# return result`)
- No excessive inline documentation that pads line count without adding information
- No hedging language in docstrings (`This method attempts to...`, `This function tries to...`)
- No redundant variable assignments introduced purely for readability theatre
- No over-engineered abstractions that exist because they felt architecturally satisfying, not because they solve a real problem

### Remove vibecoding patterns
- No copy-paste blocks that should be a function or loop
- No parallel code paths that diverged because it was easier than refactoring
- No deeply nested conditionals that can be flattened with early returns
- No dead feature flags or config options that nothing reads
- No "just in case" exception handlers that swallow errors silently

### Style
- Code reads like it was written by one person with a clear intent
- Each function does one thing
- Naming is precise -- no `data`, `info`, `result`, `temp`, `obj` as variable names without qualification

## Parser and validator audit

### Input parsing
- Every parser handles malformed input explicitly -- no silent truncation, no bare `except Exception`
- Parsing errors produce typed exceptions, not raw `ValueError` or `None` returns
- Boundary conditions tested: empty input, maximum length input, invalid encoding, unexpected whitespace

### Validation
- Every Pydantic model validator tests what it claims to test -- verify the validator body matches its field name and error message
- No validator that passes on input it should reject -- check against the actual constraint, not the test mock
- Cross-field validators check all fields they reference, not a subset
- Validators that call external state (filesystem, network) are tested with both reachable and unreachable conditions

### Data flow
- Validated data is the only data that flows past the validation boundary -- no raw input leaking past a validator into business logic
- No re-parsing of already-parsed data further down the call stack
- Sanitised inputs are not re-sanitised -- double-sanitisation can mask bugs

## Security

- No secrets, tokens, or keys in code or test fixtures
- No debug endpoints or logging statements that expose internal state
- No `assert` statements used for security-critical checks -- assert is stripped by Python's `-O` flag
- Every new attack surface has a corresponding entry in THREAT_MODEL.md
- Every new audit event is documented in the audit log spec

## Async correctness

- No blocking calls inside async functions -- no `time.sleep`, synchronous file I/O, or `subprocess` without async equivalents
- No unawaited coroutines
- No shared mutable state accessed across async boundaries without locks

## Dependency hygiene

- No new dependency added without a corresponding entry in pyproject.toml
- No pinned version that conflicts with existing constraints
- No optional dependency imported unconditionally

## Error handling

- Errors logged at the right level -- no `logger.error` for expected conditions, no `logger.debug` for security events
- Every exception that should reach the audit log does
- No exception path that silently continues when it should halt
- No bare `except Exception` or `except BaseException` without a specific reason in a comment

## Constraints
- Gates must stay green: ruff check, ruff format, mypy strict, pytest --cov-fail-under=90
- Do not touch files outside those changed in this slice
