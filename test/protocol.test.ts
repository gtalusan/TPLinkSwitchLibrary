import { describe, expect, it } from 'vitest';
import {
  assemblePacket,
  bitmaskToPorts,
  HEADER_LENGTH,
  packHeader,
  packTlvs,
  PACKET_END,
  parseBandwidthEntry,
  parseCableTestResult,
  parseIp,
  parseMac,
  parseMirrorConfig,
  parseMtuVlanConfig,
  parsePoeExtend,
  parsePoePort,
  parsePoeSystem,
  parsePortConfig,
  parsePortVlanEntry,
  parsePvid,
  parseQosPriority,
  parseStormControl,
  parseString,
  parseVlan,
  portsToBitmask,
  serializeBandwidthEntry,
  serializeIp,
  serializeMac,
  serializeMirrorConfig,
  serializeMtuVlanConfig,
  serializePoeExtend,
  serializePoePort,
  serializePoeSystemLimit,
  serializePortConfig,
  serializePortVlanEntry,
  serializePvid,
  serializeQosPriority,
  serializeStormControl,
  serializeString,
  serializeVlan,
  splitPacket,
  unpackHeader,
  unpackTlvs,
} from '../src/protocol.js';
import { FlowControl, OpCode, PoePriority, PortSpeed, TlvType } from '../src/types.js';

describe('header', () => {
  it('round-trips', () => {
    const h = {
      version: 1,
      opCode: OpCode.GET,
      switchMac: Buffer.from([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
      hostMac: Buffer.from([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]),
      sequenceId: 42,
      errorCode: 0,
      checkLength: 100,
      fragmentOffset: 0,
      flag: 0,
      tokenId: 0x1234,
      checksum: 0,
    };
    const back = unpackHeader(packHeader(h));
    expect(back.opCode).toBe(OpCode.GET);
    expect(back.switchMac.equals(h.switchMac)).toBe(true);
    expect(back.hostMac.equals(h.hostMac)).toBe(true);
    expect(back.sequenceId).toBe(42);
    expect(back.tokenId).toBe(0x1234);
    expect(back.checkLength).toBe(100);
  });
});

describe('tlv', () => {
  it('round-trips', () => {
    const entries = [
      { type: TlvType.HOSTNAME, value: Buffer.from('switch1\0') },
      { type: TlvType.NUM_PORTS, value: Buffer.from([16]) },
      { type: TlvType.PVID, value: Buffer.from([1, 0, 10]) },
    ];
    const back = unpackTlvs(packTlvs(entries));
    expect(back).toHaveLength(3);
    expect(back[0].type).toBe(TlvType.HOSTNAME);
    expect(back[1].value[0]).toBe(16);
  });

  it('stops at 0xffff terminator', () => {
    const buf = Buffer.concat([
      packTlvs([{ type: TlvType.NUM_PORTS, value: Buffer.from([8]) }]),
      PACKET_END,
      Buffer.from([0xde, 0xad]),
    ]);
    const back = unpackTlvs(buf);
    expect(back).toHaveLength(1);
  });
});

describe('packet assembly', () => {
  it('sets checkLength and appends terminator', () => {
    const h = {
      version: 1,
      opCode: OpCode.DISCOVERY,
      switchMac: Buffer.alloc(6),
      hostMac: Buffer.alloc(6),
      sequenceId: 0,
      errorCode: 0,
      checkLength: 0,
      fragmentOffset: 0,
      flag: 0,
      tokenId: 0,
      checksum: 0,
    };
    const pkt = assemblePacket(h, [{ type: TlvType.TYPE, value: Buffer.alloc(0) }]);
    const expected = HEADER_LENGTH + 4 + PACKET_END.length; // one empty TLV
    expect(pkt.length).toBe(expected);
    const parsed = splitPacket(pkt);
    expect(parsed.header.checkLength).toBe(expected);
    expect(pkt.subarray(pkt.length - 4).equals(PACKET_END)).toBe(true);
  });
});

describe('value helpers', () => {
  it('parses and serializes ip', () => {
    expect(parseIp(serializeIp('192.168.1.2'))).toBe('192.168.1.2');
  });

  it('parses and serializes mac', () => {
    expect(parseMac(serializeMac('aa:bb:cc:dd:ee:ff'))).toBe('AA:BB:CC:DD:EE:FF');
  });

  it('parses null-terminated strings', () => {
    expect(parseString(serializeString('hello'))).toBe('hello');
  });

  it('round-trips port config', () => {
    const p = {
      port: 3,
      enabled: true,
      lag: 0,
      speed: PortSpeed.AUTO,
      actualSpeed: PortSpeed.M1000_FULL,
      flowControl: FlowControl.OFF,
      actualFlowControl: FlowControl.OFF,
    };
    expect(parsePortConfig(serializePortConfig(p))).toEqual(p);
  });

  it('round-trips pvid', () => {
    const p = { port: 5, pvid: 100 };
    expect(parsePvid(serializePvid(p))).toEqual(p);
  });

  it('round-trips vlan with bitmask members', () => {
    const v = {
      vlanId: 10,
      name: 'office',
      memberPorts: [1, 2, 3, 5],
      taggedPorts: [1],
      untaggedPorts: [2, 3, 5],
    };
    const parsed = parseVlan(serializeVlan(v));
    expect(parsed.vlanId).toBe(10);
    expect(parsed.name).toBe('office');
    expect(parsed.memberPorts).toEqual([1, 2, 3, 5]);
    expect(parsed.taggedPorts).toEqual([1]);
    expect(parsed.untaggedPorts).toEqual([2, 3, 5]);
  });
});

describe('mirror / qos / bandwidth / storm', () => {
  it('round-trips mirror config', () => {
    const cfg = { enabled: true, mirrorPort: 1, ingressPorts: [2, 3, 4], egressPorts: [5] };
    expect(parseMirrorConfig(serializeMirrorConfig(cfg))).toEqual(cfg);
  });

  it('round-trips qos priority', () => {
    expect(parseQosPriority(serializeQosPriority({ port: 7, priority: 3 }))).toEqual({ port: 7, priority: 3 });
  });

  it('round-trips bandwidth entry', () => {
    const e = { port: 5, enabled: true, rateKbps: 1000 };
    expect(parseBandwidthEntry(serializeBandwidthEntry(e))).toEqual(e);
  });

  it('zeroes bandwidth rate when disabled', () => {
    const e = { port: 2, enabled: false, rateKbps: 9999 };
    const back = parseBandwidthEntry(serializeBandwidthEntry(e));
    expect(back.enabled).toBe(false);
    expect(back.rateKbps).toBe(0);
  });

  it('round-trips storm control', () => {
    const e = {
      port: 3,
      enabled: true,
      broadcastEnabled: true,
      multicastEnabled: false,
      unknownUnicastEnabled: true,
      rateKbps: 500_000,
    };
    expect(parseStormControl(serializeStormControl(e))).toEqual(e);
  });

  it('parses 9-byte storm control rows from TL-SG1024DE v7', () => {
    const row = parseStormControl(Buffer.from('150100000100000400', 'hex'));
    expect(row).toEqual({
      port: 21,
      enabled: true,
      unknownUnicastEnabled: false,
      multicastEnabled: false,
      broadcastEnabled: true,
      rateKbps: 1024,
    });
  });
});

describe('mtu-vlan / port-vlan / cable test', () => {
  it('round-trips mtu vlan', () => {
    const c = { enabled: true, uplinkPort: 3 };
    expect(parseMtuVlanConfig(serializeMtuVlanConfig(c))).toEqual(c);
  });

  it('round-trips port-based VLAN entry', () => {
    const e = { vlanId: 7, memberPorts: [1, 4, 8] };
    expect(parsePortVlanEntry(serializePortVlanEntry(e))).toEqual(e);
  });

  it('parses a cable test result', () => {
    const b = Buffer.from([3, 2, 0, 0, 0, 15]); // port 3, OPEN at 15m
    const r = parseCableTestResult(b);
    expect(r.port).toBe(3);
    expect(r.type).toBe('open');
    expect(r.distanceMeters).toBe(15);
  });
});

describe('poe', () => {
  it('parses system counters', () => {
    const b = Buffer.alloc(10);
    b.writeUInt16BE(650, 0);   // limit 65 W
    b.writeUInt16BE(0, 2);
    b.writeUInt16BE(650, 4);
    b.writeUInt16BE(123, 6);   // consumption 12.3 W
    b.writeUInt16BE(527, 8);   // remain 52.7 W
    const sys = parsePoeSystem(b);
    expect(sys.powerLimit).toBe(650);
    expect(sys.powerConsumption).toBe(123);
    expect(sys.powerRemain).toBe(527);
  });

  it('round-trips port config set payload', () => {
    const p = {
      port: 2,
      enabled: true,
      priority: PoePriority.HIGH,
      limitDeciwatt: 300,
    };
    const buf = serializePoePort(p);
    expect(buf.length).toBe(5);
    expect(buf.readUInt16BE(3)).toBe(300);
  });

  it('parses a full port status row', () => {
    const b = Buffer.alloc(14);
    b.writeUInt8(4, 0);           // port 4
    b.writeUInt8(1, 1);           // enabled
    b.writeUInt8(PoePriority.MIDDLE, 2);
    b.writeUInt16BE(330, 3);      // auto limit
    b.writeUInt16BE(42, 5);       // 4.2 W drawn
    b.writeUInt16BE(85, 7);       // 85 mA
    b.writeUInt16BE(490, 9);      // 49.0 V
    b.writeUInt16BE(70, 11);      // class 2
    b.writeUInt8(1, 13);          // power status 1
    const row = parsePoePort(b);
    expect(row.port).toBe(4);
    expect(row.enabled).toBe(true);
    expect(row.priority).toBe(PoePriority.MIDDLE);
    expect(row.limitDeciwatt).toBe(330);
    expect(row.pdClassDeciwatt).toBe(70);
    expect(row.powerStatus).toBe(1);
  });

  it('round-trips extend entry', () => {
    const e = { port: 6, enabled: true };
    expect(parsePoeExtend(serializePoeExtend(e))).toEqual(e);
  });

  it('system-limit set payload is exactly two bytes', () => {
    const buf = serializePoeSystemLimit(650);
    expect(buf.length).toBe(2);
    expect(buf.readUInt16BE(0)).toBe(650);
  });
});

describe('bitmask helpers', () => {
  it('portsToBitmask', () => {
    expect(portsToBitmask([1, 3, 5])).toBe(0b10101);
    expect(portsToBitmask([])).toBe(0);
    expect(portsToBitmask([1])).toBe(1);
  });

  it('bitmaskToPorts', () => {
    expect(bitmaskToPorts(0b10101)).toEqual([1, 3, 5]);
    expect(bitmaskToPorts(0)).toEqual([]);
  });

  it('round-trips', () => {
    const ports = [2, 4, 8, 16, 24];
    expect(bitmaskToPorts(portsToBitmask(ports))).toEqual(ports);
  });
});
