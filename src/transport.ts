import dgram from 'node:dgram';
import os from 'node:os';
import { decode, encode } from './cipher.js';
import { HEADER_LENGTH, splitPacket } from './protocol.js';

export const SWITCH_PORT = 29808;
export const CLIENT_PORT = 29809;
export const BROADCAST_ADDR = '255.255.255.255';

export interface HostInterface {
  name: string;
  ip: string;
  mac: Buffer;
}

export function resolveInterface(name?: string): HostInterface {
  const all = os.networkInterfaces();
  const candidates: HostInterface[] = [];
  for (const [ifname, addrs] of Object.entries(all)) {
    if (!addrs) continue;
    if (name && ifname !== name) continue;
    for (const a of addrs) {
      if (a.family !== 'IPv4' || a.internal) continue;
      if (!a.mac || a.mac === '00:00:00:00:00:00') continue;
      candidates.push({
        name: ifname,
        ip: a.address,
        mac: Buffer.from(a.mac.split(':').map((p) => parseInt(p, 16))),
      });
    }
  }
  if (!candidates.length) throw new Error(`no suitable IPv4 interface${name ? ` named ${name}` : ''}`);
  return candidates[0];
}

export class UdpTransport {
  readonly host: HostInterface;
  private send_: dgram.Socket;
  private recv_: dgram.Socket;
  private queue: Buffer[] = [];
  private waiters: Array<(b: Buffer) => void> = [];
  private ready: Promise<void>;
  private closed = false;

  constructor(interfaceName?: string) {
    this.host = resolveInterface(interfaceName);
    this.send_ = dgram.createSocket({ type: 'udp4', reuseAddr: true });
    this.recv_ = dgram.createSocket({ type: 'udp4', reuseAddr: true });

    this.recv_.on('message', (msg) => {
      let plain: Buffer;
      try {
        plain = decode(msg);
      } catch {
        return;
      }
      if (plain.length < HEADER_LENGTH) return;
      // ignore own outgoing broadcast echo: client sends opcodes 0/1/3
      const op = plain.readInt8(1);
      if (op !== 2 && op !== 4) return;
      const w = this.waiters.shift();
      if (w) w(plain);
      else this.queue.push(plain);
    });

    this.ready = new Promise<void>((resolve, reject) => {
      let pending = 2;
      const done = () => { if (--pending === 0) resolve(); };
      this.send_.once('error', reject);
      this.recv_.once('error', reject);
      this.send_.bind({ address: this.host.ip, port: CLIENT_PORT, exclusive: false }, () => {
        try { this.send_.setBroadcast(true); } catch { /* ignore */ }
        done();
      });
      this.recv_.bind({ address: '0.0.0.0', port: CLIENT_PORT, exclusive: false }, () => {
        try { this.recv_.setBroadcast(true); } catch { /* ignore */ }
        done();
      });
    });
  }

  async start(): Promise<void> {
    await this.ready;
  }

  async send(packet: Buffer): Promise<void> {
    await this.ready;
    const enc = encode(packet);
    await new Promise<void>((resolve, reject) => {
      this.send_.send(enc, 0, enc.length, SWITCH_PORT, BROADCAST_ADDR, (err) => {
        if (err) reject(err); else resolve();
      });
    });
  }

  async receive(timeoutMs: number): Promise<Buffer> {
    await this.ready;
    if (this.queue.length) return this.queue.shift()!;
    return new Promise<Buffer>((resolve, reject) => {
      const t = setTimeout(() => {
        const idx = this.waiters.indexOf(w);
        if (idx >= 0) this.waiters.splice(idx, 1);
        reject(new Error(`receive timed out after ${timeoutMs}ms`));
      }, timeoutMs);
      const w = (b: Buffer) => { clearTimeout(t); resolve(b); };
      this.waiters.push(w);
    });
  }

  async receiveAll(timeoutMs: number): Promise<Buffer[]> {
    await this.ready;
    const deadline = Date.now() + timeoutMs;
    const out: Buffer[] = [...this.queue];
    this.queue = [];
    while (true) {
      const remain = deadline - Date.now();
      if (remain <= 0) break;
      try {
        const p = await this.receive(remain);
        out.push(p);
      } catch {
        break;
      }
    }
    return out;
  }

  // assembles fragmented responses keyed by sequenceId
  async receiveAssembled(timeoutMs: number): Promise<Buffer> {
    const deadline = Date.now() + timeoutMs;
    const chunks: Buffer[] = [];
    let expectedSeq: number | null = null;
    while (true) {
      const remain = Math.max(0, deadline - Date.now());
      const pkt = await this.receive(remain || 1);
      const { header } = splitPacket(pkt);
      if (expectedSeq === null) expectedSeq = header.sequenceId;
      else if (header.sequenceId !== expectedSeq) continue;
      chunks.push(pkt);
      if (header.fragmentOffset === 0) break;
    }
    return chunks[chunks.length - 1];
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    try { this.send_.close(); } catch { /* ignore */ }
    try { this.recv_.close(); } catch { /* ignore */ }
  }
}
