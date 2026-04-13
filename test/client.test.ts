import { describe, expect, it } from 'vitest';
import {
  assemblePacket,
  buildSwitchInfo,
  serializeIp,
  serializeMac,
  serializeString,
  splitPacket,
  unpackTlvs,
} from '../src/protocol.js';
import { OpCode, TlvType } from '../src/types.js';

describe('end-to-end packet round-trip', () => {
  it('builds a discovery-like response and parses SwitchInfo', () => {
    const tlvs = [
      { type: TlvType.TYPE, value: serializeString('TL-SG1024DE') },
      { type: TlvType.HOSTNAME, value: serializeString('switch1') },
      { type: TlvType.MAC, value: serializeMac('00:11:22:33:44:55') },
      { type: TlvType.IP_ADDR, value: serializeIp('192.168.1.10') },
      { type: TlvType.IP_MASK, value: serializeIp('255.255.255.0') },
      { type: TlvType.GATEWAY, value: serializeIp('192.168.1.1') },
      { type: TlvType.FIRMWARE, value: serializeString('1.0.0') },
      { type: TlvType.HARDWARE, value: serializeString('v2') },
      { type: TlvType.DHCP, value: Buffer.from([0]) },
      { type: TlvType.NUM_PORTS, value: Buffer.from([24]) },
    ];
    const header = {
      version: 1,
      opCode: OpCode.SET,
      switchMac: serializeMac('00:11:22:33:44:55'),
      hostMac: serializeMac('aa:bb:cc:dd:ee:ff'),
      sequenceId: 1,
      errorCode: 0,
      checkLength: 0,
      fragmentOffset: 0,
      flag: 0,
      tokenId: 0,
      checksum: 0,
    };
    const pkt = assemblePacket(header, tlvs);
    const { payload } = splitPacket(pkt);
    const info = buildSwitchInfo(unpackTlvs(payload));
    expect(info.type).toBe('TL-SG1024DE');
    expect(info.hostname).toBe('switch1');
    expect(info.mac).toBe('00:11:22:33:44:55'.toUpperCase());
    expect(info.ipAddress).toBe('192.168.1.10');
    expect(info.numPorts).toBe(24);
    expect(info.dhcp).toBe(false);
  });
});
