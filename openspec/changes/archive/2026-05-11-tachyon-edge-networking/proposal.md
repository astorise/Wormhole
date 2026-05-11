# Proposal: Shared UDP Egress and Tachyon Virtual Sockets

## Problem
The current implementation has two significant networking blockers for production deployment on Tachyon-Mesh:
1. **UDP NAT Breakage:** The `egress_loop` in the FaaS relay uses an ephemeral port (`0.0.0.0:0`) to send UDP replies back to remote callers. This breaks NATs and firewalls, which expect UDP replies to originate from the same port the request was sent to (e.g., 443).
2. **Missing WASI/WIT Bindings:** The relay still binds standard OS sockets (`tokio::net::TcpListener`, `UdpSocket`). When running in Tachyon's `wasm32-wasi` worker mode, standard socket binding may be restricted or unsupported. The `SocketSource::Tachyon` branch is currently unimplemented.

## Proposed Solution
1. **Shared Egress Socket:** Pass a shared reference (`Arc<UdpSocket>`) of the `UdpIngress` socket into the FaaS relay's `egress_loop`. This ensures all egress datagrams use the correct source port.
2. **Tachyon Virtual Socket Abstraction:** Abstract the socket creation. When compiling for `wasm32-wasi`, use Tachyon's host bindings (e.g., injecting the socket via the host interface) instead of standard OS bindings. We will implement the `SocketSource::Tachyon` logic to interface with `accelerator-host.wit` concepts.

## Non-Goals
- Implementing the actual Tachyon host-side Rust runtime (we only implement the guest-side Wasm bindings).