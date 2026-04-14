# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

```bash
make                # Build authentication.so shared library
make test           # Run tests (disabled in CI; requires PostgreSQL at smartmet-test:5444)
make format         # Run clang-format on all source and test files
make clean          # Remove build artifacts
make rpm            # Build RPM package
make configtest     # Validate test configuration with cfgvalidate
make install        # Install library and headers (PREFIX=/usr)
```

Tests are in `test/` and require a live PostgreSQL database with the authentication schema populated. There is a single test binary (`EngineTest`) covering access grants, denials, wildcards, and unknown API keys.

## Architecture

This is a SmartMet Server engine that provides API key authorization by loading access control mappings from PostgreSQL into memory.

### Two-class pattern: base + implementation

**`Engine`** (header-only base in `authentication/Engine.h`) is the public interface that plugins link against. Its entire implementation lives in the header so plugins can load without the engine being configured. The default methods throw "Not implemented" or return disabled status.

**`AuthEngine`** (in `authentication/Engine.cpp`) is the concrete implementation, instantiated only when the engine is enabled. It is not exported in the header -- plugins only see the base `Engine` class and call virtual methods.

The factory function `engine_class_creator()` at the bottom of `Engine.cpp` decides which to instantiate: base `Engine` (disabled/no config) or `AuthEngine` (enabled).

### Data model

PostgreSQL holds two tables (configurable names):
- **token table**: defines `(service, token, value)` triples -- what values each token grants
- **auth table**: maps `(apikey, service, token)` -- which tokens each API key holds; token `"*"` means wildcard (universal access)

These are loaded into an in-memory hierarchy: `AuthEngine` -> `Service` -> `Token` -> values (set of strings). Both `Service` and `Token` are internal classes defined only in `Engine.cpp`.

### Authorization flow

1. Plugin calls `authorize(apikey, tokenvalue(s), service)`
2. Read lock acquired on `itsMutex`
3. Service looked up; wildcard API keys get immediate grant
4. For known API keys, each requested value is checked against the token sets
5. Unknown API keys fall back to `defaultAccessAllow` config setting
6. `explicitGrantOnly` parameter bypasses wildcard and unknown-key defaults

### Background refresh

`AuthEngine::init()` loads mappings, then spawns an `Fmi::AsyncTask` that calls `rebuildMappings()` every `updateIntervalSeconds`. The full mapping is rebuilt atomically and swapped in under a write lock.

## Configuration

Engine config is libconfig format with a `database` group:
- `host`, `port`, `database`, `schema`, `username`, `password` -- PostgreSQL connection
- `auth_table`, `token_table` -- table names
- `update_interval_seconds` -- refresh period

Top-level settings:
- `default_access_is_allow` -- policy for unknown API keys (true = allow, false = deny)
- `disabled` -- set to `true` to load the dummy base Engine instead
