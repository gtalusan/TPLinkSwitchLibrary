import { assemblePacket, buildSwitchInfo, splitPacket, unpackTlvs } from './protocol.js';
import { UdpTransport } from './transport.js';
import { DiscoveredSwitch, OpCode, PacketHeader, TlvType } from './types.js';

export interface DiscoverOptions {
  interface?: string;
  timeout?: number;
}

export async function discoverSwitches(opts: DiscoverOptions = {}): Promise<DiscoveredSwitch[]> {
  const timeout = opts.timeout ?? 2000;
  const t = new UdpTransport(opts.interface);
  try {
    await t.start();
    const header: PacketHeader = {
      version: 1,
      opCode: OpCode.DISCOVERY,
      switchMac: Buffer.alloc(6),
      hostMac: t.host.mac,
      sequenceId: Math.floor(Math.random() * 1000),
      errorCode: 0,
      checkLength: 0,
      fragmentOffset: 0,
      flag: 0,
      tokenId: 0,
      checksum: 0,
    };
    // Discovery payload is empty (header + PACKET_END only). Sending a stub TLV
    // (even type=1/TYPE with empty value) causes firmware to drop the packet.
    const pkt = assemblePacket(header, []);
    await t.send(pkt);
    const responses = await t.receiveAll(timeout);
    const seen = new Set<string>();
    const out: DiscoveredSwitch[] = [];
    for (const r of responses) {
      try {
        const { header: h, payload } = splitPacket(r);
        if (h.opCode !== OpCode.SET) continue;
        const tlvs = unpackTlvs(payload);
        const info = buildSwitchInfo(tlvs);
        if (!info.mac || seen.has(info.mac)) continue;
        seen.add(info.mac);
        out.push({ info, sourceInterface: t.host.name, sourceIp: t.host.ip });
      } catch {
        // ignore malformed
      }
    }
    return out;
  } finally {
    t.close();
  }
}
