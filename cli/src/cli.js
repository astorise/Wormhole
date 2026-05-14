#!/usr/bin/env node
import { Command } from 'commander';
import { Wormhole } from './index.js';

const program = new Command();

function collectPortMapping(value, previous) {
  previous.push(parsePortMapping(value));
  return previous;
}

function parsePortMapping(value) {
  const parts = value.split(':').map((part) => part.trim());
  if (parts.length > 2 || parts.some((part) => part.trim() === '')) {
    throw new Error(`invalid port mapping: ${value}`);
  }

  const publicPort = parsePort(parts[0], 'public');
  const localPort = parsePort(parts[1] ?? parts[0], 'local');
  return { publicPort, localPort };
}

function parsePort(value, label) {
  const port = Number.parseInt(value, 10);
  if (!Number.isInteger(port) || port < 1 || port > 65535 || String(port) !== value) {
    throw new Error(`invalid ${label} port: ${value}`);
  }
  return port;
}

program
  .name('wormhole')
  .description('Universal L4 transport tunnel over QUIC with end-to-end mTLS')
  .version('0.2.0')
  .requiredOption('--relay <url>', 'Relay server URL (e.g. relay.tachyon.io:4433)')
  .option('--tcp <public:local>', 'TCP port mapping to expose', collectPortMapping, [])
  .option('--udp <public:local>', 'UDP port mapping to expose', collectPortMapping, [])
  .option('--cert <path>', 'Path to client certificate (.pem)')
  .option('--key <path>', 'Path to client private key (.pem)')
  .option('--ca <path>', 'Path to relay CA certificate (.pem) — pins relay trust anchor, prevents MITM')
  .option('--unsecure', 'Disable relay certificate verification; only for local development')
  .option('--sni <name>', 'SNI hostname to advertise to the relay')
  .action(async (opts) => {
    const targets = [];
    for (const target of opts.tcp) targets.push({ protocol: 'tcp', ...target });
    for (const target of opts.udp) targets.push({ protocol: 'udp', ...target });

    if (targets.length === 0) {
      console.error('Error: specify at least one of --tcp or --udp');
      process.exit(1);
    }

    const tunnel = await Wormhole.create({
      relay: opts.relay,
      targets,
      sni: opts.sni,
      auth: opts.cert && opts.key ? { cert: opts.cert, key: opts.key } : undefined,
      ca: opts.ca,
      unsecure: opts.unsecure,
    });

    console.log(`Wormhole open: ${tunnel.endpoint}`);

    process.on('SIGINT', () => { tunnel.close(); process.exit(0); });
    process.on('SIGTERM', () => { tunnel.close(); process.exit(0); });
  });

program.parse();
