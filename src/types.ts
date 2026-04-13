export enum OpCode {
  DISCOVERY = 0,
  GET = 1,
  SET = 2,
  LOGIN = 3,
  RETURN = 4,
  READ5 = 5,
}

export enum TlvType {
  TYPE = 1,
  HOSTNAME = 2,
  MAC = 3,
  IP_ADDR = 4,
  IP_MASK = 5,
  GATEWAY = 6,
  FIRMWARE = 7,
  HARDWARE = 8,
  DHCP = 9,
  NUM_PORTS = 10,
  LED_STATUS = 12,
  AUTO_SAVE = 13,
  IS_FACTORY = 14,
  FLASH_TYPE = 15,
  USERNAME = 512,
  PASSWORD = 514,
  REBOOT = 773,
  SAVE = 2304,
  GET_TOKEN_ID = 2305,
  PORTS = 4096,
  IGMP_SNOOPING = 4352,
  TRUNK = 4608,
  MTU_VLAN = 8192,
  VLAN_ENABLED = 8704,
  VLAN = 8705,
  PVID = 8706,
  VLAN_FILLER = 8707,
  QOS_MODE = 12288,
  QOS_PRIORITY = 12289,
  PORT_STATISTICS = 16384,
  PORT_MIRROR = 16640,
  LOOP_PREVENTION = 17152,
  END = 0xffff,
}

export enum PortSpeed {
  LINK_DOWN = 0,
  AUTO = 1,
  M10_HALF = 2,
  M10_FULL = 3,
  M100_HALF = 4,
  M100_FULL = 5,
  M1000_FULL = 6,
}

export enum FlowControl {
  OFF = 0,
  ON = 1,
}

export interface PacketHeader {
  version: number;
  opCode: OpCode;
  switchMac: Buffer;
  hostMac: Buffer;
  sequenceId: number;
  errorCode: number;
  checkLength: number;
  fragmentOffset: number;
  flag: number;
  tokenId: number;
  checksum: number;
}

export interface TlvEntry {
  type: number;
  value: Buffer;
}

export interface SwitchInfo {
  type: string;
  hostname: string;
  mac: string;
  ipAddress: string;
  subnetMask: string;
  gateway: string;
  firmware: string;
  hardware: string;
  dhcp: boolean;
  numPorts: number;
}

export interface PortConfig {
  port: number;
  enabled: boolean;
  lag: number;
  speed: PortSpeed;
  actualSpeed: PortSpeed;
  flowControl: FlowControl;
  actualFlowControl: FlowControl;
}

export interface PortStatistics {
  port: number;
  status: number;
  txGood: number;
  txBad: number;
  rxGood: number;
  rxBad: number;
}

export interface VlanConfig {
  vlanId: number;
  name: string;
  memberPorts: number[];
  taggedPorts: number[];
  untaggedPorts: number[];
}

export interface PvidConfig {
  port: number;
  pvid: number;
}

export interface QosConfig {
  mode: boolean;
  priorities: Buffer;
}

export interface MirrorConfig {
  raw: Buffer;
}

export interface SwitchConfig {
  info: SwitchInfo;
  ports: PortConfig[];
  vlans: VlanConfig[];
  pvids: PvidConfig[];
  vlanEnabled: boolean;
  igmpSnooping: boolean;
  qos: QosConfig;
  mirror: MirrorConfig;
  loopPrevention: boolean;
  statistics: PortStatistics[];
}

export interface DiscoveredSwitch {
  info: SwitchInfo;
  sourceInterface: string;
  sourceIp: string;
}

export interface SwitchClientOptions {
  switchMac: string;
  interface?: string;
  username?: string;
  password?: string;
  timeout?: number;
}
