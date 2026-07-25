# GTA-Claw container deployment

The container image runs the native Rust daemon and publishes only its bounded health endpoint.

```text
docker build -t gta-claw ..
docker run -d --name gta-claw --restart unless-stopped -p 3978:3978 gta-claw
curl http://127.0.0.1:3978/health
```

The image defaults `GTA_CLAW_BIND` to `0.0.0.0:3978`, runs as an unprivileged user, and checks the
live endpoint with `gta-claw-daemon --probe-http`.

`run.sh` remains the deployment wrapper for pulling/building, restarting, inspecting, and stopping
the image. Compatibility configuration files under `deploy/conf/` are migration inputs for the
typed Rust configuration work; they are not injected into the current health-only daemon and do not
enable script execution.
