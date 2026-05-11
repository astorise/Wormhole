# Tasks: Dev Mode Implementation

## Phase 1: CLI Auto-Generation
- [x] 1. Add `node-forge` to `cli/package.json` dependencies for cross-platform X.509 generation.
- [x] 2. Create `cli/src/certs.js` to handle credential discovery. Implement a function to check `~/.ssh/<domain>.pem` and `.key`.
- [x] 3. In `cli/src/certs.js`, implement a fallback function that generates a self-signed certificate in memory if the SSH folder lacks the files.
- [x] 4. Update `cli/src/index.js` and `quic.js` to utilize this new discovery/generation logic seamlessly when explicit auth paths are omitted.

## Phase 2: FaaS Unsecure Mode
- [x] 5. Update `faas/src/main.rs` to parse a new environment variable `WORMHOLE_UNSECURE` (boolean).
- [x] 6. Pass this flag into the `Relay::bind` and subsequently to the `tls::server_config` function.
- [x] 7. Modify `faas/src/tls.rs` to bypass `WebPkiClientVerifier` and use `with_no_client_auth()` when the unsecure flag is true.
- [x] 8. Update the routing key extraction in `faas/src/relay.rs` to fallback to the unverified SNI (`HandshakeData::server_name`) if the connection is unauthenticated.

## Phase 3: Validation
- [x] 9. Add a test in `cli/test/wormhole.test.js` verifying that the fallback certificate generator outputs valid PEM strings.
- [x] 10. Ensure the CLI logs a helpful message (e.g., `[Auth] Auto-generated ephemeral certificate for <SNI>`) so the user understands what happened.