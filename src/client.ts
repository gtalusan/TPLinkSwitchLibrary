import { EventEmitter } from 'node:events';
import {
  assemblePacket,
  buildSwitchInfo,
  parseBool,
  parsePortConfig,
  parsePortStats,
  parsePvid,
  parseVlan,
  serializeBool,
  serializeMac,
  serializePortConfig,
  serializePvid,
  serializeString,
  serializeVlan,
  splitPacket,
  unpackTlvs,
} from './protocol.js';
import { UdpTransport } from './transport.js';
import {
  MirrorConfig,
  OpCode,
  PacketHeader,
  PortConfig,
  PortStatistics,
  PvidConfig,
  QosConfig,
  SwitchClientOptions,
  SwitchConfig,
  SwitchInfo,
  TlvEntry,
  TlvType,
  VlanConfig,
} from './types.js';

export class SwitchClient extends EventEmitter {
  private opts: Required<SwitchClientOptions>;
  private transport?: UdpTransport;
  private switchMac: Buffer;
  private sequenceId = Math.floor(Math.random() * 1000);
  private tokenId = 0;

  constructor(opts: SwitchClientOptions) {
    super();
    this.opts = {
      switchMac: opts.switchMac,
      interface: opts.interface ?? '',
      username: opts.username ?? 'admin',
      password: opts.password ?? 'admin',
      timeout: opts.timeout ?? 2000,
    };
    this.switchMac = serializeMac(opts.switchMac);
  }

  private async transport_(): Promise<UdpTransport> {
    if (!this.transport) {
      this.transport = new UdpTransport(this.opts.interface || undefined);
      await this.transport.start();
    }
    return this.transport;
  }

  private nextSeq(): number {
    this.sequenceId = (this.sequenceId + 1) % 1000;
    return this.sequenceId;
  }

  private buildHeader(opCode: OpCode, hostMac: Buffer): PacketHeader {
    return {
      version: 1,
      opCode,
      switchMac: this.switchMac,
      hostMac,
      sequenceId: this.nextSeq(),
      errorCode: 0,
      checkLength: 0,
      fragmentOffset: 0,
      flag: 0,
      tokenId: this.tokenId,
      checksum: 0,
    };
  }

  private async query(opCode: OpCode, tlvs: TlvEntry[]): Promise<{ header: PacketHeader; tlvs: TlvEntry[] }> {
    const t = await this.transport_();
    const header = this.buildHeader(opCode, t.host.mac);
    const packet = assemblePacket(header, tlvs);
    await t.send(packet);
    const reply = await t.receiveAssembled(this.opts.timeout);
    const { header: rh, payload } = splitPacket(reply);
    this.tokenId = rh.tokenId;
    if (rh.errorCode !== 0) {
      const err = new Error(`switch returned error code ${rh.errorCode}`);
      this.emit('error', err);
      throw err;
    }
    return { header: rh, tlvs: unpackTlvs(payload) };
  }

  private async refreshToken(): Promise<void> {
    await this.query(OpCode.GET, [{ type: TlvType.GET_TOKEN_ID, value: Buffer.alloc(0) }]);
  }

  private loginTlvs(): TlvEntry[] {
    return [
      { type: TlvType.USERNAME, value: serializeString(this.opts.username, true) },
      { type: TlvType.PASSWORD, value: serializeString(this.opts.password, true) },
    ];
  }

  async login(): Promise<void> {
    // Matches pc-smrt: refresh token, then send LOGIN with just credentials.
    // This establishes the session; subsequent reads use plain GET with the
    // inherited token_id. Writes re-run refresh+LOGIN with credentials+payload.
    await this.refreshToken();
    await this.query(OpCode.LOGIN, this.loginTlvs());
  }

  private async authedSet(tlvs: TlvEntry[]): Promise<{ header: PacketHeader; tlvs: TlvEntry[] }> {
    await this.refreshToken();
    return this.query(OpCode.LOGIN, [...this.loginTlvs(), ...tlvs]);
  }

  async getInfo(): Promise<SwitchInfo> {
    // Firmware quirk: GET must carry exactly one query TLV. Any info query
    // returns every info field, so asking for hostname yields the full set.
    const { tlvs } = await this.query(OpCode.GET, [{ type: TlvType.HOSTNAME, value: Buffer.alloc(0) }]);
    return buildSwitchInfo(tlvs);
  }

  async getPorts(): Promise<PortConfig[]> {
    const { tlvs } = await this.query(OpCode.GET, [{ type: TlvType.PORTS, value: Buffer.alloc(0) }]);
    return tlvs.filter((t) => t.type === TlvType.PORTS).map((t) => parsePortConfig(t.value));
  }

  async setPorts(ports: PortConfig[]): Promise<void> {
    await this.authedSet(ports.map((p) => ({ type: TlvType.PORTS, value: serializePortConfig(p) })));
  }

  async getPortStatistics(): Promise<PortStatistics[]> {
    const { tlvs } = await this.query(OpCode.GET, [{ type: TlvType.PORT_STATISTICS, value: Buffer.alloc(0) }]);
    return tlvs.filter((t) => t.type === TlvType.PORT_STATISTICS).map((t) => parsePortStats(t.value));
  }

  async getVlanEnabled(): Promise<boolean> {
    const { tlvs } = await this.query(OpCode.GET, [{ type: TlvType.VLAN_ENABLED, value: Buffer.alloc(0) }]);
    const t = tlvs.find((x) => x.type === TlvType.VLAN_ENABLED);
    return t ? parseBool(t.value) : false;
  }

  async setVlanEnabled(enabled: boolean): Promise<void> {
    await this.authedSet([{ type: TlvType.VLAN_ENABLED, value: serializeBool(enabled) }]);
  }

  async getVlans(): Promise<VlanConfig[]> {
    const { tlvs } = await this.query(OpCode.GET, [{ type: TlvType.VLAN, value: Buffer.alloc(0) }]);
    return tlvs.filter((t) => t.type === TlvType.VLAN && t.value.length >= 10).map((t) => parseVlan(t.value));
  }

  async setVlan(vlan: VlanConfig): Promise<void> {
    // firmware bug: set exactly one VLAN per request
    await this.authedSet([{ type: TlvType.VLAN, value: serializeVlan(vlan) }]);
  }

  async deleteVlan(vlanId: number): Promise<void> {
    await this.setVlan({ vlanId, name: '', memberPorts: [], taggedPorts: [], untaggedPorts: [] });
  }

  async getPvids(): Promise<PvidConfig[]> {
    const { tlvs } = await this.query(OpCode.GET, [{ type: TlvType.PVID, value: Buffer.alloc(0) }]);
    return tlvs.filter((t) => t.type === TlvType.PVID && t.value.length === 3).map((t) => parsePvid(t.value));
  }

  async setPvid(port: number, pvid: number): Promise<void> {
    await this.setPvids([{ port, pvid }]);
  }

  async setPvids(pvids: PvidConfig[]): Promise<void> {
    await this.authedSet(pvids.map((p) => ({ type: TlvType.PVID, value: serializePvid(p) })));
  }

  async getIgmpSnooping(): Promise<boolean> {
    const { tlvs } = await this.query(OpCode.GET, [{ type: TlvType.IGMP_SNOOPING, value: Buffer.alloc(0) }]);
    const t = tlvs.find((x) => x.type === TlvType.IGMP_SNOOPING);
    return t ? parseBool(t.value) : false;
  }

  async setIgmpSnooping(enabled: boolean): Promise<void> {
    await this.authedSet([{ type: TlvType.IGMP_SNOOPING, value: serializeBool(enabled) }]);
  }

  async getQos(): Promise<QosConfig> {
    // One TLV per GET — ask for mode, the switch also returns priority entries.
    const { tlvs } = await this.query(OpCode.GET, [{ type: TlvType.QOS_MODE, value: Buffer.alloc(0) }]);
    const mode = parseBool(tlvs.find((x) => x.type === TlvType.QOS_MODE)?.value ?? Buffer.alloc(0));
    const priorities = Buffer.concat(
      tlvs.filter((x) => x.type === TlvType.QOS_PRIORITY).map((x) => x.value),
    );
    return { mode, priorities };
  }

  async getMirror(): Promise<MirrorConfig> {
    const { tlvs } = await this.query(OpCode.GET, [{ type: TlvType.PORT_MIRROR, value: Buffer.alloc(0) }]);
    const t = tlvs.find((x) => x.type === TlvType.PORT_MIRROR);
    return { raw: t ? t.value : Buffer.alloc(0) };
  }

  async getLoopPrevention(): Promise<boolean> {
    const { tlvs } = await this.query(OpCode.GET, [{ type: TlvType.LOOP_PREVENTION, value: Buffer.alloc(0) }]);
    const t = tlvs.find((x) => x.type === TlvType.LOOP_PREVENTION);
    return t ? parseBool(t.value) : false;
  }

  async setLoopPrevention(enabled: boolean): Promise<void> {
    await this.authedSet([{ type: TlvType.LOOP_PREVENTION, value: serializeBool(enabled) }]);
  }

  async getFullConfig(): Promise<SwitchConfig> {
    const [info, ports, vlans, pvids, vlanEnabled, igmpSnooping, qos, mirror, loopPrevention, statistics] =
      await Promise.all([
        this.getInfo(),
        this.getPorts(),
        this.getVlans(),
        this.getPvids(),
        this.getVlanEnabled(),
        this.getIgmpSnooping(),
        this.getQos(),
        this.getMirror(),
        this.getLoopPrevention(),
        this.getPortStatistics(),
      ]);
    return { info, ports, vlans, pvids, vlanEnabled, igmpSnooping, qos, mirror, loopPrevention, statistics };
  }

  async save(): Promise<void> {
    await this.authedSet([{ type: TlvType.SAVE, value: Buffer.from([1]) }]);
  }

  async reboot(): Promise<void> {
    await this.authedSet([{ type: TlvType.REBOOT, value: Buffer.from([1]) }]);
  }

  close(): void {
    this.transport?.close();
    this.transport = undefined;
  }
}
