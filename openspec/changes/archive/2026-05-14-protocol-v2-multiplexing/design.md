# Design: V2 Framing Protocol

## 1. The V2 Protocol Header
The framing is extremely lightweight to minimize CPU and bandwidth overhead.
- **Header Structure:** exactly 2 bytes (`u16` in Big-Endian format) containing the public port number the remote caller connected to.
- For TCP: Sent once at the very beginning of the bidirectional QUIC stream.
- For UDP: Prepended to the payload of every QUIC datagram.

## 2. FaaS Egress Modifications (Rust)
In `faas/src/router.rs`:
- Update `route_ingress` to accept the `ingress_port: u16`. Write this `u16` to the `quic_send` stream before writing the `initial` ClientHello bytes.
- Update `route_udp_ingress` to prepend the `ingress_port` to the datagram payload before calling `send_datagram`.

## 3. CLI Routing Engine (Node.js)
In `cli/src/mux.js`:
- `Multiplexer` now maintains a routing table: `Map<number, net.Server | dgram.Socket>` mapping public ports to local servers.
- **Stream Interception:** When the dialer yields a new stream, read the first 2 bytes. Look up the local TCP server mapped to that port, and pipe the remainder of the stream to a new connection to that local server.
- **Datagram Interception:** When a datagram arrives from the dialer, extract the first 2 bytes, slice the buffer, and send the payload to the mapped local UDP socket.

## 4. CLI Argument Parsing
In `cli/src/cli.js`:
- Parse strings like `443:8443` into `{ publicPort: 443, localPort: 8443 }`. If only a single number is provided, assume `publicPort === localPort`.