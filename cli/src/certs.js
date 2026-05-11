/**
 * Dev-mode credential helpers.
 *
 * Credential resolution order (when no explicit --cert/--key are provided):
 *   1. ~/.ssh/<relayHost>.pem + ~/.ssh/<relayHost>.key
 *   2. Auto-generated ephemeral self-signed cert (in memory, never written to disk)
 */

import { homedir } from 'node:os';
import { join } from 'node:path';
import { existsSync, readFileSync } from 'node:fs';

/**
 * Try to read a certificate pair from the user's ~/.ssh/ directory.
 *
 * @param {string} relayHost  Hostname portion of the relay address.
 * @returns {{ cert: string, key: string, source: 'ssh', raw: true } | null}
 */
export function discoverCerts(relayHost) {
  const sshDir = join(homedir(), '.ssh');
  const certPath = join(sshDir, `${relayHost}.pem`);
  const keyPath = join(sshDir, `${relayHost}.key`);

  if (existsSync(certPath) && existsSync(keyPath)) {
    return {
      cert: readFileSync(certPath, 'utf8'),
      key: readFileSync(keyPath, 'utf8'),
      source: 'ssh',
      raw: true,
    };
  }
  return null;
}

/**
 * Generate an in-memory self-signed X.509 certificate.
 * The certificate's SAN DNS name is set to `sni` so the relay can identify
 * the client by its intended service name without external PKI.
 *
 * Note: RSA 2048-bit key generation is CPU-bound and may take ~1-3 seconds.
 * This is acceptable for a one-time dev-mode bootstrap.
 *
 * @param {string} sni  DNS name to embed as Subject Alternative Name.
 * @returns {Promise<{ cert: string, key: string, source: 'ephemeral', raw: true }>}
 */
export async function generateEphemeralCert(sni) {
  // Dynamic import keeps the heavy node-forge out of the hot path when
  // explicit certs are provided.
  const { default: forge } = await import('node-forge');
  const { pki, md } = forge;

  const keys = pki.rsa.generateKeyPair(2048);
  const cert = pki.createCertificate();

  cert.publicKey = keys.publicKey;
  cert.serialNumber = '01';
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);

  const subject = [{ name: 'commonName', value: sni }];
  cert.setSubject(subject);
  cert.setIssuer(subject);
  cert.setExtensions([
    {
      name: 'subjectAltName',
      altNames: [{ type: 2 /* dNSName */, value: sni }],
    },
  ]);

  cert.sign(keys.privateKey, md.sha256.create());

  return {
    cert: pki.certificateToPem(cert),
    key: pki.privateKeyToPem(keys.privateKey),
    source: 'ephemeral',
    raw: true,
  };
}
