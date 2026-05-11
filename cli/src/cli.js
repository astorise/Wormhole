#!/usr/bin/env node
import { Command } from 'commander';
import { Wormhole } from './index.js';

const program = new Command();

program
  .name('wormhole')
  .description('Universal L4 transport tunnel over QUIC with end-to-end mTLS')
  .version('0.1.0')
  .requiredOption('--relay <url>', 'Relay server URL (e.g. relay.tachyon.io:4433)')
  .option('--tcp <port>', 'Local TCP port to expose', (v) => parseInt(v, 10))
  .option('--udp <port>', 'Local UDP port to expose', (v) => parseInt(v, 10))
  .option('--cert <path>', 'Path to client certificate (.pem)')
  .option('--key <path>', 'Path to client private key (.pem)')
  .option('--sni <name>', 'SNI hostname to advertise to the relay')
  .action(async (opts) => {
    const targets = [];
    if (opts.tcp) targets.push({ protocol: 'tcp', port: opts.tcp });
    if (opts.udp) targets.push({ protocol: 'udp', port: opts.udp });

    if (targets.length === 0) {
      console.error('Error: specify at least one of --tcp or --udp');
      process.exit(1);
    }

    const tunnel = await Wormhole.create({
      relay: opts.relay,
      targets,
      sni: opts.sni,
      auth: opts.cert && opts.key ? { cert: opts.cert, key: opts.key } : undefined,
    });

    console.log(`Wormhole open: ${tunnel.endpoint}`);

    process.on('SIGINT', () => { tunnel.close(); process.exit(0); });
    process.on('SIGTERM', () => { tunnel.close(); process.exit(0); });
  });

program.parse();
