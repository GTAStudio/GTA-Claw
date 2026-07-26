# gta-claw-daemon

Headless GTA Claw daemon. The process loads configuration, binds the HTTP
surface from `claw-http-api`, and shuts down gracefully on a termination
signal.

## Modes

```
gta-claw-daemon           # load configuration, bind, and serve until signalled
gta-claw-daemon --probe   # print runtime health once and exit 0
```

`--probe` performs no configuration load and binds nothing, so it remains
usable as a container healthcheck.

## Startup

1. Configuration is migrated from the process environment by `claw-config`
   using the frozen legacy mapping in `crates/claw-config/data/env-mapping.json`.
   Invalid configuration stops startup with an operator-facing message on
   standard error and a nonzero exit; the process never starts half-configured.
2. The listener binds `0.0.0.0:<core.server.port>`, matching the interface the
   legacy Node server used so a published container port still reaches it.
3. Three lines are written to standard output, in order, only after the socket
   is bound and signal handlers are installed:

   ```
   ready protocol=1
   healthy runtime=<os>-<arch>
   listening address=0.0.0.0:3978 domain=localhost
   ```

The smallest environment the frozen contract accepts is the same one the legacy
product required:

| Variable | Requirement |
| --- | --- |
| `AGENT_ROLE_URL` | Absolute HTTP(S) URL, always required |
| `GITHUB_TOKEN` | Required unless `DEVICE_FLOW_ENABLED=true` with `GITHUB_CLIENT_ID` |
| `ENABLE_TEAMS` | Defaults to `true`, which then requires `MicrosoftAppId` and `MicrosoftAppPassword` |
| `PORT` | Optional, defaults to `3978` |

Values that belong to deploy, build, or CI scopes are reported on standard
error as manual migrations rather than silently ignored.

## Shutdown

`SIGTERM` and `SIGINT` on POSIX, and `CTRL_C`, `CTRL_BREAK`, `CTRL_CLOSE`, and
`CTRL_SHUTDOWN` on Windows, stop the listener, drain in-flight requests, write
`shutdown signal=<name>`, and exit `0`.

## Current limits

Channel adapters, the agent engine, skill and role loading, and the updater are
not wired into this process. Their ports report `Unavailable`, and `/ready`
answers `503` while naming them, so readiness never claims a dependency that is
absent. No bearer credential is installed because `claw-config` exposes the
administrator token only as an unreadable secret reference, so the protected
routes answer `401`.
