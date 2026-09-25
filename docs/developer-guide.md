# Authentication engine developer guide

This guide is for developers who change `smartmet-engine-authentication`, or use it from a
plugin. The engine answers one question: may this API key use these values of this
service? It loads the access rules from PostgreSQL into memory and refreshes them in the
background. The wms and avi plugins use it (for example to restrict WMS layers).

[CLAUDE.md](../CLAUDE.md) has the architecture summary.

## Contents

1. [Building and testing](#1-building-and-testing)
2. [Data model](#2-data-model)
3. [The API and its decisions](#3-the-api-and-its-decisions)
4. [Refresh](#4-refresh)
5. [Configuration](#5-configuration)
6. [Compatibility](#6-compatibility)
7. [Known pitfalls](#7-known-pitfalls)

---

## 1. Building and testing

```bash
make
make test          # EngineTest; needs PostgreSQL at smartmet-test:5444 with the schema (not run in CI)
make configtest    # cfgvalidate on the test configuration
```

## 2. Data model

Two tables (names configurable):

* **token table** `(service, token, value)`: which values a token grants in a service, for
  example service `wms`, token `radar`, value `Radar:suomi_dbz`;
* **auth table** `(apikey, service, token)`: which tokens an API key holds. The token `*` is
  a wildcard: the key may use every value of the service.

They are loaded into memory as service → tokens → values, and apikey → tokens per service.

The API key itself comes from the request: plugins read it with spine's
`FmiApiKey::getFmiApiKey(request)`.

## 3. The API and its decisions

```cpp
bool authorize(const std::string& apikey, const std::string& value,
               const std::string& service, bool explicitGrantOnly = false) const;
bool authorize(const std::string& apikey, const std::vector<std::string>& values,
               const std::string& service) const;
bool isEnabled() const;
```

The decision, in order:

| Situation | Single value | List of values |
|-----------|--------------|----------------|
| service has no rules at all | allow, unless `explicitGrantOnly` | **allow** |
| API key unknown for the service | `default_access_is_allow`; deny with `explicitGrantOnly` | `default_access_is_allow` |
| key has the wildcard token | allow (unless `explicitGrantOnly`) | allow |
| value granted by one of the key's tokens | allow | continue with the next value |
| value not granted | deny | deny |

The base `Engine` class is header-only: when the engine is disabled
(`disabled = true` or no configuration), plugins get it, `isEnabled()` is false, and the
plugin skips authorisation.

## 4. Refresh

`init()` loads the rules, then an `Fmi::AsyncTask` rebuilds them every
`update_interval_seconds` and swaps the new mapping in under the write lock. `authorize()`
takes the read lock. A failed refresh is printed, and the previous rules stay in use.

## 5. Configuration

| Key | Meaning |
|-----|---------|
| `database.host`, `.port`, `.database`, `.schema`, `.username`, `.password` | PostgreSQL connection. |
| `database.auth_table`, `database.token_table` | Table names. |
| `database.update_interval_seconds` | Refresh period. |
| `default_access_is_allow` | Policy for API keys the service does not know. |
| `disabled` | Load the header-only base engine instead. |

## 6. Compatibility

`authorize()` is virtual and implemented in the header's base class; add new methods at
the end of the class only.

## 7. Known pitfalls

* **Services without rules fail open.** A service name with no rows in the token table (a
  typo in a plugin, or a service whose rules were never loaded) allows every request. The
  list form always allows; the single-value form allows unless `explicitGrantOnly` is set.
  The unmerged `origin/security` branch changes this ("fails open for unknown services");
  update this section when it is merged.
* **`default_access_is_allow = true` makes unknown keys pass.** Only keys that appear in the
  auth table for the service are restricted.
* **The wildcard token bypasses the value checks** for that service.
* **Refresh latency.** Revoking a key takes effect at the next refresh.
