# smartmet-engine-authentication

Part of [SmartMet Server](https://github.com/fmidev/smartmet-server). See the [SmartMet Server documentation](https://github.com/fmidev/smartmet-server) for a full overview of the ecosystem.

## Overview

The authentication engine provides API key authentication and access control for SmartMet Server. It validates API keys in incoming requests and enforces per-key access permissions.

## Running without a database (dummy mode)

The engine can be loaded in a dummy mode that needs no database. Plugins that look up the
Authentication engine then still start, but the dummy has no API keys behind it and its
access checks throw `Not implemented`, so a plugin must not be configured to authenticate
requests with it. Dummy mode is enabled in either of two ways:

1. Leave the engine's configuration file unspecified or set it to an empty string in the
   server configuration:

   ```
   engines:
   {
     authentication:
     {
       configfile = "";   # or omit configfile entirely
     };
   };
   ```

2. Give a configuration file that sets the engine's own disable flag. No other settings
   are read, so this line alone is enough:

   ```
   disabled = true;
   ```

Setting `disabled = true` in the server's `engines.authentication` section is different:
the server then does not load `authentication.so` at all, and any plugin that requires the
engine fails at startup.

## Documentation

- [Developer guide](docs/developer-guide.md) — data model, authorisation decisions, refresh, configuration, pitfalls

## License

MIT — see [LICENSE](LICENSE)

## Contributing

Bug reports and pull requests are welcome on [GitHub](../../issues).
