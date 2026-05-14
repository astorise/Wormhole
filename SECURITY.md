# Security Policy

## Threat Model

Wormhole uses an outbound QUIC tunnel from the CLI to the relay. The relay exposes public TCP and UDP ingress ports, maps traffic to a registered tunnel identity, and pushes framed traffic down to the CLI. The CLI strips Wormhole framing and forwards traffic to loopback services.

Production deployments should use `WORMHOLE_CA_CERT` so the relay requires client certificates. Tunnel identity is derived from the verified certificate SAN. `WORMHOLE_DEV=1` disables client authentication and is only intended for local development.

Relay-generated development certificates are persisted under `WORMHOLE_RELAY_CERT_DIR` when set, or `/tmp` by default. Persist that directory if clients pin the relay certificate across restarts.

## Reporting Vulnerabilities

Do not open public issues for suspected vulnerabilities. Email the maintainers with:

- affected commit or release
- configuration details
- reproduction steps
- expected and actual security impact

The maintainers will acknowledge reports, assess severity, and coordinate a fix before public disclosure.
