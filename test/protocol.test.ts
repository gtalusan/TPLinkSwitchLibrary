import { describe, expect, it } from 'vitest';
import {
  assemblePacket,
  bitmaskToPorts,
  HEADER_LENGTH,
  packHeader,
  packTlvs,
  PACKET_END,
  parseIp,
  parseMac,
  parsePortConfig,
  parsePvid,
  parseString,
  parseVlan,
  portsToBitmask,
  serializeIp,
  serializeMac,
  serializePortConfig,
  serializePvid,
  serializeString,
  serializeVlan,
  splitPacket,
  unpackHeader,
  unpackTlvs,
} from '../src/protocol.js';
import { FlowControl, OpCode, PortSpeed, TlvType } from '../src/types.js';

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
