import {
  FlowControl,
  OpCode,
  PacketHeader,
  PortConfig,
  PortSpeed,
  PortStatistics,
  PvidConfig,
  SwitchInfo,
  TlvEntry,
  TlvType,
  VlanConfig,
} from './types.js';

export const HEADER_LENGTH = 32;
export const PACKET_END = Buffer.from([0xff, 0xff, 0x00, 0x00]);

export function packHeader(h: PacketHeader): Buffer {
  const b = Buffer.alloc(HEADER_LENGTH);
  b.writeInt8(h.version, 0);
  b.writeInt8(h.opCode, 1);
  if (h.switchMac.length !== 6) throw new Error('switchMac must be 6 bytes');
  if (h.hostMac.length !== 6) throw new Error('hostMac must be 6 bytes');
  h.switchMac.copy(b, 2);
  h.hostMac.copy(b, 8);
  b.writeInt16BE(h.sequenceId, 14);
  b.writeInt32BE(h.errorCode, 16);
  b.writeInt16BE(h.checkLength, 20);
  b.writeInt16BE(h.fragmentOffset, 22);
  b.writeInt16BE(h.flag, 24);
  b.writeInt16BE(h.tokenId, 26);
  b.writeInt32BE(h.checksum, 28);
  return b;
}

export function unpackHeader(buf: Buffer): PacketHeader {
  if (buf.length < HEADER_LENGTH) throw new Error('buffer too short for header');
  return {
    version: buf.readInt8(0),
    opCode: buf.readInt8(1) as OpCode,
    switchMac: Buffer.from(buf.subarray(2, 8)),
    hostMac: Buffer.from(buf.subarray(8, 14)),
    sequenceId: buf.readInt16BE(14),
    errorCode: buf.readInt32BE(16),
    checkLength: buf.readInt16BE(20),
    fragmentOffset: buf.readInt16BE(22),
    flag: buf.readInt16BE(24),
    tokenId: buf.readInt16BE(26),
    checksum: buf.readInt32BE(28),
  };
}

export function packTlvs(entries: TlvEntry[]): Buffer {
  const parts: Buffer[] = [];
  for (const e of entries) {
    const hdr = Buffer.alloc(4);
    hdr.writeUInt16BE(e.type, 0);
    hdr.writeUInt16BE(e.value.length, 2);
    parts.push(hdr, e.value);
  }
  return Buffer.concat(parts);
}

export function unpackTlvs(buf: Buffer): TlvEntry[] {
  const out: TlvEntry[] = [];
  let o = 0;
  while (o + 4 <= buf.length) {
    const type = buf.readUInt16BE(o);
    const len = buf.readUInt16BE(o + 2);
    if (type === 0xffff) break;
    if (o + 4 + len > buf.length) throw new Error('TLV length overruns buffer');
    out.push({ type, value: Buffer.from(buf.subarray(o + 4, o + 4 + len)) });
    o += 4 + len;
  }
  return out;
}

export function assemblePacket(header: PacketHeader, tlvs: TlvEntry[]): Buffer {
  const payload = packTlvs(tlvs);
  const total = HEADER_LENGTH + payload.length + PACKET_END.length;
  const h = { ...header, checkLength: total };
  return Buffer.concat([packHeader(h), payload, PACKET_END]);
}

export function splitPacket(data: Buffer): { header: PacketHeader; payload: Buffer } {
  if (data.length < HEADER_LENGTH + 4) throw new Error('packet too short');
  const header = unpackHeader(data.subarray(0, HEADER_LENGTH));
  // Trailing 4 bytes should be PACKET_END; slice everything between header and end.
  const payload = Buffer.from(data.subarray(HEADER_LENGTH, data.length - PACKET_END.length));
  return { header, payload };
}

// ---------- value parsers ----------

export function parseString(b: Buffer): string {
  let end = b.length;
  for (let i = 0; i < b.length; i++) if (b[i] === 0) { end = i; break; }
  return b.subarray(0, end).toString('utf8');
}

export function parseIp(b: Buffer): string {
  if (b.length !== 4) throw new Error('ip must be 4 bytes');
  return `${b[0]}.${b[1]}.${b[2]}.${b[3]}`;
}

export function parseMac(b: Buffer): string {
  if (b.length !== 6) throw new Error('mac must be 6 bytes');
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join(':').toUpperCase();
}

export function parseBool(b: Buffer): boolean {
  return b.length > 0 && b[0] !== 0;
}

export function parsePortConfig(b: Buffer): PortConfig {
  if (b.length !== 7) throw new Error('port config must be 7 bytes');
  return {
    port: b[0],
    enabled: b[1] !== 0,
    lag: b[2],
    speed: b[3] as PortSpeed,
    actualSpeed: b[4] as PortSpeed,
    flowControl: b[5] as FlowControl,
    actualFlowControl: b[6] as FlowControl,
  };
}

export function parseVlan(b: Buffer): VlanConfig {
  if (b.length < 10) throw new Error('vlan too short');
  const vlanId = b.readUInt16BE(0);
  const memberMask = b.readUInt32BE(2);
  const taggedMask = b.readUInt32BE(6);
  const name = parseString(b.subarray(10));
  const memberPorts = bitmaskToPorts(memberMask);
  const taggedPorts = bitmaskToPorts(taggedMask);
  const untaggedPorts = memberPorts.filter((p) => !taggedPorts.includes(p));
  return { vlanId, name, memberPorts, taggedPorts, untaggedPorts };
}

export function parsePvid(b: Buffer): PvidConfig {
  if (b.length !== 3) throw new Error('pvid must be 3 bytes');
  return { port: b.readUInt8(0), pvid: b.readUInt16BE(1) };
}

export function parsePortStats(b: Buffer): PortStatistics {
  if (b.length < 19) throw new Error('port stats must be >= 19 bytes');
  // Python struct: !bbbiiii ; python packs int32. JS uses UInt32BE for counters.
  return {
    port: b.readUInt8(0),
    status: b.readUInt8(1),
    // byte 2 is an unknown/pad
    txGood: b.readUInt32BE(3),
    txBad: b.readUInt32BE(7),
    rxGood: b.readUInt32BE(11),
    rxBad: b.readUInt32BE(15),
  };
}

// ---------- value serializers ----------

export function serializeString(s: string, nullTerminate = true): Buffer {
  const body = Buffer.from(s, 'utf8');
  return nullTerminate ? Buffer.concat([body, Buffer.from([0])]) : body;
}

export function serializeIp(ip: string): Buffer {
  const parts = ip.split('.').map((p) => parseInt(p, 10));
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) {
    throw new Error(`invalid ip ${ip}`);
  }
  return Buffer.from(parts);
}

export function serializeMac(mac: string): Buffer {
  const parts = mac.split(/[:-]/).map((p) => parseInt(p, 16));
  if (parts.length !== 6 || parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) {
    throw new Error(`invalid mac ${mac}`);
  }
  return Buffer.from(parts);
}

export function serializeBool(v: boolean): Buffer {
  return Buffer.from([v ? 1 : 0]);
}

export function serializePortConfig(p: PortConfig): Buffer {
  return Buffer.from([
    p.port,
    p.enabled ? 1 : 0,
    p.lag,
    p.speed,
    p.actualSpeed,
    p.flowControl,
    p.actualFlowControl,
  ]);
}

export function serializeVlan(v: VlanConfig): Buffer {
  const head = Buffer.alloc(10);
  head.writeUInt16BE(v.vlanId, 0);
  head.writeUInt32BE(portsToBitmask(v.memberPorts), 2);
  head.writeUInt32BE(portsToBitmask(v.taggedPorts), 6);
  return Buffer.concat([head, serializeString(v.name, true)]);
}

export function serializePvid(p: PvidConfig): Buffer {
  const b = Buffer.alloc(3);
  b.writeUInt8(p.port, 0);
  b.writeUInt16BE(p.pvid, 1);
  return b;
}

// ---------- bitmask helpers ----------

export function portsToBitmask(ports: number[]): number {
  let m = 0;
  for (const p of ports) {
    if (p < 1 || p > 32) throw new Error(`port ${p} out of range`);
    m |= 1 << (p - 1);
  }
  return m >>> 0;
}

export function bitmaskToPorts(mask: number): number[] {
  const out: number[] = [];
  for (let i = 0; i < 32; i++) {
    if ((mask >>> i) & 1) out.push(i + 1);
  }
  return out;
}

// ---------- high-level helpers ----------

export function buildSwitchInfo(tlvs: TlvEntry[]): SwitchInfo {
  const info: Partial<SwitchInfo> = {
    type: '',
    hostname: '',
    mac: '',
    ipAddress: '',
    subnetMask: '',
    gateway: '',
    firmware: '',
    hardware: '',
    dhcp: false,
    numPorts: 0,
  };
  for (const t of tlvs) {
    switch (t.type) {
      case TlvType.TYPE: info.type = parseString(t.value); break;
      case TlvType.HOSTNAME: info.hostname = parseString(t.value); break;
      case TlvType.MAC: info.mac = parseMac(t.value); break;
      case TlvType.IP_ADDR: info.ipAddress = parseIp(t.value); break;
      case TlvType.IP_MASK: info.subnetMask = parseIp(t.value); break;
      case TlvType.GATEWAY: info.gateway = parseIp(t.value); break;
      case TlvType.FIRMWARE: info.firmware = parseString(t.value); break;
      case TlvType.HARDWARE: info.hardware = parseString(t.value); break;
      case TlvType.DHCP: info.dhcp = parseBool(t.value); break;
      case TlvType.NUM_PORTS: info.numPorts = t.value.readUInt8(0); break;
    }
  }
  return info as SwitchInfo;
}

export const TLV_NAMES: Record<number, string> = Object.fromEntries(
  Object.entries(TlvType).filter(([, v]) => typeof v === 'number').map(([k, v]) => [v as number, k]),
);
