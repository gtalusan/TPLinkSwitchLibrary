# tplink-escp: TP-Link Easy Smart Configuration Protocol Library

## Goal

Build a modern, well-documented TypeScript library that implements the TP-Link Easy Smart Configuration Protocol (ESCP) — the proprietary UDP-based protocol used by TP-Link Easy Smart switches (TL-SG105E, TL-SG108E, TL-SG116E, TL-SG1016DE, TL-SG1024DE, TL-SG108PE, etc.). This replaces the Windows-only Java "Easy Smart Configuration Utility" (ESCU) with a cross-platform Node.js library suitable for use as the backend for the existing `tplink-switch-ui` project.

---

## Prior Art & Protocol Reference

The protocol has been fully reverse-engineered by multiple independent researchers. The following sources were studied in detail and should be referenced during implementation:

### Source Code (cloned and analyzed)

| Repo | Description | Key Takeaways |
|------|-------------|---------------|
| `pklaus/smrt` | Original Python implementation | Core protocol structure, RC4-like cipher with hardcoded 256-byte key, header format, TLV payload structure |
| `philippechataignon/smrt` | Improved fork | Cleaner Protocol class, interface-based discovery, VLAN set/delete, PVID set, stats parsing |
| `rgl/ansible-collection-tp-link-easy-smart-switch` | Ansible collection wrapping smrt | High-level `SmrtSwitchClient` with get/set for ports, VLANs, PVIDs; `SmrtSwitch` with config diffing; firmware bug workarounds (set VLANs one at a time) |
| `chrisdcmoore.co.uk` blog post | Protocol reverse engineering writeup | Full packet header field map, TLV structure, vulnerability disclosure (unauthenticated GET), token mechanics |

### Protocol Summary

**Transport**: UDP broadcast. Client sends from port `29809` to `255.255.255.255:29808`. Switch replies from port `29808` to `255.255.255.255:29809`.

**Encryption**: RC4-variant stream cipher. Hardcoded 256-byte key (same in all firmware and the ESCU Java app). Encode and decode are the same function (symmetric). The key is:

```
[191, 155, 227, 202, 99, 162, 79, 104, 49, 18, 190, 164, 30,
76, 189, 131, 23, 52, 86, 106, 207, 125, 126, 169, 196, 28, 172, 58,
188, 132, 160, 3, 36, 120, 144, 168, 12, 231, 116, 44, 41, 97, 108,
213, 42, 198, 32, 148, 218, 107, 247, 112, 204, 14, 66, 68, 91, 224,
206, 235, 33, 130, 203, 178, 1, 134, 199, 78, 249, 123, 7, 145, 73,
208, 209, 100, 74, 115, 72, 118, 8, 22, 243, 147, 64, 96, 5, 87, 60,
113, 233, 152, 31, 219, 143, 174, 232, 153, 245, 158, 254, 70, 170,
75, 77, 215, 211, 59, 71, 133, 214, 157, 151, 6, 46, 81, 94, 136,
166, 210, 4, 43, 241, 29, 223, 176, 67, 63, 186, 137, 129, 40, 248,
255, 55, 15, 62, 183, 222, 105, 236, 197, 127, 54, 179, 194, 229,
185, 37, 90, 237, 184, 25, 156, 173, 26, 187, 220, 2, 225, 0, 240,
50, 251, 212, 253, 167, 17, 193, 205, 177, 21, 181, 246, 82, 226,
38, 101, 163, 182, 242, 92, 20, 11, 95, 13, 230, 16, 121, 124, 109,
195, 117, 39, 98, 239, 84, 56, 139, 161, 47, 201, 51, 135, 250, 10,
19, 150, 45, 111, 27, 24, 142, 80, 85, 83, 234, 138, 216, 57, 93,
65, 154, 141, 122, 34, 140, 128, 238, 88, 89, 9, 146, 171, 149, 53,
102, 61, 114, 69, 217, 175, 103, 228, 35, 180, 252, 200, 192, 165,
159, 221, 244, 110, 119, 48]
```

**Packet Structure**:

```
32-byte header + N TLV tuples + 4-byte terminator (FF FF 00 00)
```

**Header format** (big-endian, struct format `!bb6s6shihhhhi`):

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 1 | `version` | Protocol version, always `0x01` |
| 1 | 1 | `op_code` | 0=DISCOVERY, 1=GET, 2=SET, 3=LOGIN, 4=RETURN, 5=READ5 |
| 2 | 6 | `switch_mac` | Target switch MAC (zeroes for discovery) |
| 8 | 6 | `host_mac` | Client/host MAC address |
| 14 | 2 | `sequence_id` | Sequence number for request/response correlation |
| 16 | 4 | `error_code` | 0 = OK |
| 20 | 2 | `check_length` | Total packet length including header and terminator |
| 22 | 2 | `fragment_offset` | For fragmented responses |
| 24 | 2 | `flag` | Unknown/unused |
| 26 | 2 | `token_id` | Session token, refreshed before SET/LOGIN |
| 28 | 4 | `checksum` | Unused (always zeroes in practice) |

**Request/Response op_code pairs**:
- Discovery: client sends `0` (DISCOVERY), switch replies `2` (SET)
- Query: client sends `1` (GET), switch replies `2` (SET)
- Login/Change: client sends `3` (LOGIN), switch replies `4` (RETURN)

**TLV Payload**: Each entry is `[type: u16][length: u16][value: u8[length]]`. Multiple TLVs per packet. Packet ends with `0xFFFF0000`.

**Known TLV Type IDs**:

| ID | Name | Value Format | Read/Write |
|----|------|-------------|------------|
| 1 | type | string | R |
| 2 | hostname | string | R/W |
| 3 | mac | 6 bytes (MAC) | R |
| 4 | ip_addr | 4 bytes (IPv4) | R/W |
| 5 | ip_mask | 4 bytes (IPv4) | R/W |
| 6 | gateway | 4 bytes (IPv4) | R/W |
| 7 | firmware | string | R |
| 8 | hardware | string | R |
| 9 | dhcp | bool (1 byte) | R/W |
| 10 | num_ports | u8 | R |
| 11 | management_vlan | u16 | R/W |
| 12 | led_status | bool | R/W |
| 13 | auto_save | bool | R |
| 14 | is_factory | bool | R |
| 15 | flash_type | hex | R |
| 512 | username | string (null-terminated) | W (login) |
| 513 | password_old | string (null-terminated) | W (credential change) |
| 514 | password | string (null-terminated) | W (login) |
| 515 | password_new | string (null-terminated) | W (credential change) |
| 528 | rsa_key | opaque | R/W |
| 768 | system_config_get | opaque | R |
| 769 | system_config_set | opaque | W |
| 773 | reboot | bool | W |
| 1280 | system_reset | action | W |
| 1536 | system_upgrade | opaque | W |
| 2304 | save | action | W |
| 2305 | get_token_id | action | R |
| 4096 | ports | 7 bytes per port | R/W |
| 4352 | igmp_snooping | bool | R/W |
| 4354 | igmp_suppress | bool | R/W |
| 4608 | trunk | 5 bytes | R/W |
| 8192 | mtu_vlan | 2 bytes | R/W |
| 8448 | port_vlan_enabled | bool | R/W |
| 8449 | port_vlan_entry | `{vlan_id:u8, member_mask:u32}` | R/W |
| 8450 | port_vlan_count | u8 | R |
| 8704 | vlan_enabled | bool (hex) | R/W |
| 8705 | vlan | `{vlan_id: u16, member_mask: u32, tagged_mask: u32, name: string\0}` | R/W |
| 8706 | pvid | `{port: u8, pvid: u16}` | R/W |
| 8707 | vlan_filler | string | R (padding, ignore) |
| 8708 | mtu_vlan_management_enabled | bool | R/W |
| 8709 | mtu_vlan_management_ports | u32 port mask | R/W |
| 8710 | port_vlan_management_enabled | bool | R/W |
| 8711 | port_vlan_management_ports | u32 port mask | R/W |
| 8712 | vlan_8021q_management_enabled | bool | R/W |
| 8713 | vlan_8021q_management_vlan | u16 | R/W |
| 12288 | qos_mode | bool | R/W |
| 12289 | qos_priority | `{port:u8, priority:u8}` | R/W |
| 12544 | bandwidth_ingress | `{port:u8, enabled:u8, rate_kbps:u32}` | R/W |
| 12545 | bandwidth_egress | `{port:u8, enabled:u8, rate_kbps:u32}` | R/W |
| 12800 | storm_control | 9 bytes: port, enabled, 3 flags, rate u32 | R/W |
| 13568 | poe_system | 10-byte GET counters, 2-byte SET limit | R/W |
| 13824 | poe_port | 14-byte GET row, 5-byte SET row | R/W |
| 14080 | poe_recovery_global | bool | R/W |
| 14336 | poe_recovery_entry | model-dependent | R/W |
| 14592 | poe_extend | `{port:u8, enabled:u8}` | R/W |
| 16384 | port_statistics | `{port:u8, status:u8, pad:u8, tx_good:u32, tx_bad:u32, rx_good:u32, rx_bad:u32}` per port — struct `!bbbiiii` (19 bytes) | R |
| 16640 | port_mirror | 10 bytes | R/W |
| 16896 | cable_test | `{port:u8, result:u8, distance:u32}` | W/R |
| 17152 | loop_prevention | bool | R/W |

**Port Settings TLV (4096)** — 7-byte value per port:

```
[port_number][status][lag][speed_configured][speed_actual][flow_control_configured][flow_control_actual]
```

Speed values: `0x01`=Auto, `0x02`=10M Half, `0x03`=10M Full, `0x04`=100M Half, `0x05`=100M Full, `0x06`=1000M Full

Flow control: `0x00`=Off, `0x01`=On

**VLAN TLV (8705)** — value format: `struct !hii` + null-terminated string

```
[vlan_id: u16][member_ports_bitmask: u32][tagged_ports_bitmask: u32][name: string\0]
```

Port bitmasks: bit 0 = port 1, bit 1 = port 2, etc. To delete a VLAN, set member_mask and tagged_mask to 0.

**PVID TLV (8706)** — value format: `struct !bh`

```
[port_number: u8][pvid: u16]
```

**Login sequence**: 1) Send GET with `get_token_id` TLV (empty value) to refresh token. 2) Send LOGIN with `username` and `password` TLVs (null-terminated strings).

**SET sequence**: 1) Send GET with `get_token_id` to refresh token. 2) Send LOGIN with username + password TLVs followed by the setting TLVs in the same packet.

**Important firmware bugs/quirks (from rgl's Ansible collection)**:
- Set VLANs one at a time — setting multiple VLANs in a single packet corrupts VLAN names
- After setting PVIDs, the switch returns the resulting PVID state; verify it matches expectations
- A port must always belong to at least one VLAN

---

## Project Structure

```
tplink-escp/
├── package.json
├── tsconfig.json
├── src/
│   ├── index.ts                 # Public API barrel export
│   ├── cipher.ts                # RC4-variant encode/decode with hardcoded key
│   ├── protocol.ts              # Header/TLV pack/unpack, TLV type registry, value interpreters
│   ├── transport.ts             # UDP socket management, send/receive, broadcast, timeout handling
│   ├── discovery.ts             # Switch discovery (broadcast probe, collect responses)
│   ├── client.ts                # High-level SwitchClient: login, get/set config, typed methods
│   └── types.ts                 # All TypeScript interfaces and enums
└── test/
    ├── cipher.test.ts           # Round-trip encode/decode, known test vectors
    ├── protocol.test.ts         # Header pack/unpack, TLV serialization, value interpretation
    └── client.test.ts           # Mock transport, test login sequence, config methods
```

---

## Implementation Plan

### Phase 1: Core Protocol (`cipher.ts`, `types.ts`, `protocol.ts`)

#### `types.ts`

Define all types, enums, and interfaces:

```typescript
// Enums
enum OpCode { DISCOVERY = 0, GET = 1, SET = 2, LOGIN = 3, RETURN = 4, READ5 = 5 }
enum TlvType { TYPE = 1, HOSTNAME = 2, MAC = 3, IP_ADDR = 4, ... }
enum PortSpeed { AUTO = 1, M10_HALF = 2, M10_FULL = 3, M100_HALF = 4, M100_FULL = 5, M1000_FULL = 6 }
enum FlowControl { OFF = 0, ON = 1 }

// Interfaces
interface PacketHeader {
  version: number;
  opCode: OpCode;
  switchMac: Buffer;  // 6 bytes
  hostMac: Buffer;    // 6 bytes
  sequenceId: number;
  errorCode: number;
  checkLength: number;
  fragmentOffset: number;
  flag: number;
  tokenId: number;
  checksum: number;
}

interface TlvEntry { type: number; value: Buffer; }

interface SwitchInfo {
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

interface PortConfig {
  port: number;
  enabled: boolean;
  lag: number;
  speed: PortSpeed;
  actualSpeed: PortSpeed;
  flowControl: FlowControl;
  actualFlowControl: FlowControl;
}

interface PortStatistics {
  port: number;
  status: number;
  txGood: number;
  txBad: number;
  rxGood: number;
  rxBad: number;
}

interface VlanConfig {
  vlanId: number;
  name: string;
  memberPorts: number[];   // e.g. [1, 2, 3, 5]
  taggedPorts: number[];   // e.g. [1]
  untaggedPorts: number[]; // derived: memberPorts - taggedPorts
}

interface PvidConfig { port: number; pvid: number; }

interface QosPriority { port: number; priority: number; }

interface QosConfig {
  mode: boolean;
  priorities: QosPriority[];
}

interface MirrorConfig {
  enabled: boolean;
  mirrorPort: number;
  ingressPorts: number[];
  egressPorts: number[];
}

interface BandwidthEntry {
  port: number;
  enabled: boolean;
  rateKbps: number;
}

interface BandwidthConfig {
  ingress: BandwidthEntry[];
  egress: BandwidthEntry[];
}

interface StormControlEntry {
  port: number;
  enabled: boolean;
  broadcastEnabled: boolean;
  multicastEnabled: boolean;
  unknownUnicastEnabled: boolean;
  rateKbps: number;
}

interface IpConfig {
  dhcp: boolean;
  ipAddress?: string;
  subnetMask?: string;
  gateway?: string;
  managementVlan?: number;
}

interface MtuVlanConfig {
  enabled: boolean;
  uplinkPort: number;
}

interface PortVlanEntry {
  vlanId: number;
  memberPorts: number[];
}

interface PortVlanConfig {
  enabled: boolean;
  entries: PortVlanEntry[];
  managementStatus: boolean;
  managementPorts: number[];
}

type CableTestResultType =
  | 'no_cable'
  | 'normal'
  | 'open'
  | 'short'
  | 'open_short'
  | 'cross_cable';

interface CableTestResult {
  port: number;
  type: CableTestResultType;
  distanceMeters: number;
}

interface PoeSystem {
  powerLimit: number;
  powerLimitMin: number;
  powerLimitMax: number;
  powerConsumption: number;
  powerRemain: number;
}

enum PoePriority { HIGH = 0, MIDDLE = 1, LOW = 2 }

interface PoePortConfig {
  port: number;
  enabled: boolean;
  priority: PoePriority;
  limitDeciwatt: number;
  powerDeciwatt: number;
  currentMilliamp: number;
  voltageDecivolt: number;
  pdClassDeciwatt: number;
  powerStatus: number;
}

interface PoeExtendEntry {
  port: number;
  enabled: boolean;
}

interface SwitchConfig {
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

// Discovery result
interface DiscoveredSwitch {
  info: SwitchInfo;
  sourceInterface: string;
  sourceIp: string;
}

// Client options
interface SwitchClientOptions {
  switchMac: string;       // "AA:BB:CC:DD:EE:FF"
  interface?: string;      // network interface name, auto-detect if omitted
  username?: string;       // default "admin"
  password?: string;       // default "admin"
  timeout?: number;        // receive timeout in ms, default 2000
}
```

#### `cipher.ts`

Implement the RC4-variant cipher. The key is hardcoded. Encode and decode are the same operation.

- Export `function encode(data: Buffer): Buffer`
- Export `function decode(data: Buffer): Buffer` (alias for encode)
- The algorithm: initialize S-box from the 256-byte key, then for each byte `k` in data: `i = (k+1) & 0xFF`, `j = (j + S[i]) & 0xFF`, swap `S[i]` and `S[j]`, XOR data byte with `S[(S[i] + S[j]) & 0xFF]`
- **Critical**: the S-box must be copied from the key for each invocation (not mutated in place across calls)

#### `protocol.ts`

- `HEADER_FORMAT`: struct definition matching `!bb6s6shihhhhi` — use a manual Buffer read/write approach since Node doesn't have Python's `struct`
- `HEADER_LENGTH = 32`
- `PACKET_END = Buffer.from([0xFF, 0xFF, 0x00, 0x00])`
- `TLV_REGISTRY`: Map of TLV type ID to `{ name, valueParser, valueSerializer }`
- `function packHeader(header: PacketHeader): Buffer`
- `function unpackHeader(buf: Buffer): PacketHeader`
- `function packTlvs(entries: TlvEntry[]): Buffer`
- `function unpackTlvs(buf: Buffer): TlvEntry[]`
- `function assemblePacket(header: PacketHeader, tlvs: TlvEntry[]): Buffer` — sets `checkLength`, packs header + TLVs + PACKET_END
- `function splitPacket(data: Buffer): { header: PacketHeader; payload: Buffer }` — validates length and PACKET_END
- Value interpreters: `parseString`, `parseIp`, `parseMac`, `parseBool`, `parsePortConfig`, `parseVlan`, `parsePvid`, `parsePortStats`, `parseMirrorConfig`, `parseQosPriority`, `parseBandwidthEntry`, `parseStormControl`, `parseMtuVlanConfig`, `parsePortVlanEntry`, `parseCableTestResult`, `parsePoeSystem`, `parsePoePort`, `parsePoeExtend`
- Value serializers: `serializeString`, `serializeIp`, `serializeMac`, `serializeVlan`, `serializePvid`, `serializePortConfig`, `serializeMirrorConfig`, `serializeQosPriority`, `serializeBandwidthEntry`, `serializeStormControl`, `serializeMtuVlanConfig`, `serializePortVlanEntry`, `serializeCableTestRequest`, `serializePoeSystemLimit`, `serializePoePort`, `serializePoeExtend`
- Port bitmask helpers: `portsToBitmask(ports: number[]): number` and `bitmaskToPorts(mask: number): number[]`

### Phase 2: Transport Layer (`transport.ts`)

- `class UdpTransport`
  - Constructor takes `interfaceName?: string`
  - Auto-detects host IP and MAC from the specified (or sole non-loopback) interface using `os.networkInterfaces()`
  - Creates two UDP4 sockets:
    - Send socket: bound to `hostIp:29809`, `SO_BROADCAST` enabled
    - Receive socket: bound to `0.0.0.0:29809` (or `255.255.255.255:29809` on Linux — test both), with configurable timeout
  - `async send(packet: Buffer): Promise<void>` — sends to `255.255.255.255:29808`
  - `async receive(timeoutMs: number): Promise<Buffer>` — waits for a single response, decodes, returns raw decrypted data
  - `async receiveAll(timeoutMs: number): Promise<Buffer[]>` — collects all responses until timeout (for discovery)
  - `async receiveAssembled(timeoutMs: number, sequenceId?: number): Promise<Buffer>` — waits for response fragments matching the request sequence ID
  - `close(): void` — closes both sockets
  - Handles fragmented responses keyed by sequence ID
  - All send/receive automatically encode/decode via cipher

### Phase 3: Discovery (`discovery.ts`)

- `async function discoverSwitches(options?: { interface?: string; timeout?: number }): Promise<DiscoveredSwitch[]>`
  - Creates a UdpTransport
  - Assembles a DISCOVERY packet (opCode=0, zeroed switch_mac, host_mac from interface)
  - Sends the broadcast
  - Collects all responses within timeout (default 2000ms)
  - Parses each response's TLV payload into `DiscoveredSwitch` objects
  - Returns the array
  - Closes the transport

### Phase 4: High-Level Client (`client.ts`)

- `class SwitchClient`
  - Constructor takes `SwitchClientOptions`
  - Manages its own `UdpTransport` instance
  - Maintains `sequenceId` (random start, increment per send, mod 1000)
  - Maintains `tokenId` (updated from every response header)
  - Internal `buildHeader(opCode)` returns a populated `PacketHeader`
  - Internal `async query(opCode, tlvs): Promise<{ header, tlvs }>` — assembles, encodes, sends, receives the matching sequence ID, decodes, returns parsed TLVs
  - Internal `async refreshToken()` — sends GET with `get_token_id` TLV
  - `async login(): Promise<void>` — refreshes token, then sends LOGIN with username/password
  - `async getInfo(): Promise<SwitchInfo>` — GET with hostname TLV (switch returns all info fields)
  - `async setHostname(hostname: string): Promise<void>`
  - `async setIpConfig(cfg: IpConfig): Promise<void>`
  - `async setDhcp(enabled: boolean, managementVlan?: number): Promise<void>`
  - `async getLed(): Promise<boolean>`
  - `async setLed(enabled: boolean): Promise<void>`
  - `async setCredentials(newUsername: string, newPassword: string): Promise<void>`
  - `async factoryReset(): Promise<void>`
  - `async getPorts(): Promise<PortConfig[]>` — GET with ports TLV, parse each 7-byte value
  - `async setPorts(ports: PortConfig[]): Promise<void>` — SET with port config TLVs
  - `async getPortStatistics(): Promise<PortStatistics[]>` — GET with port_statistics TLV
  - `async getVlanEnabled(): Promise<boolean>` — GET with vlan_enabled TLV
  - `async setVlanEnabled(enabled: boolean): Promise<void>`
  - `async getVlans(): Promise<VlanConfig[]>` — GET with vlan TLV, parse bitmasks into port arrays
  - `async setVlan(vlan: VlanConfig): Promise<void>` — SET single VLAN (one at a time per firmware bug)
  - `async deleteVlan(vlanId: number): Promise<void>` — SET VLAN with zeroed bitmasks
  - `async getPvids(): Promise<PvidConfig[]>` — GET with pvid TLV
  - `async setPvid(port: number, pvid: number): Promise<void>`
  - `async setPvids(pvids: PvidConfig[]): Promise<void>` — sets multiple PVIDs (multiple TLVs in one packet)
  - `async getManagementVlan(): Promise<{ enabled: boolean; vlanId: number | null }>`
  - `async setManagementVlanEnabled(enabled: boolean): Promise<void>`
  - `async setManagementVlan(vlanId: number): Promise<void>`
  - `async getMtuVlan(): Promise<MtuVlanConfig>`
  - `async setMtuVlan(cfg: MtuVlanConfig): Promise<void>`
  - `async getPortVlanConfig(): Promise<PortVlanConfig>`
  - `async setPortVlanEnabled(enabled: boolean): Promise<void>`
  - `async setPortVlanEntry(entry: PortVlanEntry): Promise<void>`
  - `async deletePortVlanEntry(vlanId: number): Promise<void>`
  - `async getIgmpSnooping(): Promise<boolean>`
  - `async setIgmpSnooping(enabled: boolean): Promise<void>`
  - `async getIgmpReportSuppress(): Promise<boolean>`
  - `async setIgmpReportSuppress(enabled: boolean): Promise<void>`
  - `async getQos(): Promise<QosConfig>`
  - `async setQosMode(enabled: boolean): Promise<void>`
  - `async setQosPriorities(priorities: QosPriority[]): Promise<void>`
  - `async getBandwidthControl(): Promise<BandwidthConfig>`
  - `async setBandwidthIngress(entries: BandwidthEntry[]): Promise<void>`
  - `async setBandwidthEgress(entries: BandwidthEntry[]): Promise<void>`
  - `async getStormControl(): Promise<StormControlEntry[]>`
  - `async setStormControl(entries: StormControlEntry[]): Promise<void>`
  - `async getMirror(): Promise<MirrorConfig>`
  - `async setMirror(cfg: MirrorConfig): Promise<void>`
  - `async getLoopPrevention(): Promise<boolean>`
  - `async setLoopPrevention(enabled: boolean): Promise<void>`
  - `async cableTest(port: number): Promise<CableTestResult>`
  - `async getPoeSystem(): Promise<PoeSystem>`
  - `async setPoeSystemLimit(limitDeciwatt: number): Promise<void>`
  - `async getPoePorts(): Promise<PoePortConfig[]>`
  - `async setPoePort(p: { port: number; enabled: boolean; priority: PoePriority; limitDeciwatt: number }): Promise<void>`
  - `async getPoeExtend(): Promise<PoeExtendEntry[]>`
  - `async setPoeExtend(entry: PoeExtendEntry): Promise<void>`
  - `async getPoeRecoveryEnabled(): Promise<boolean>`
  - `async setPoeRecoveryEnabled(enabled: boolean): Promise<void>`
  - `async getFullConfig(): Promise<SwitchConfig>` — queries all config categories and assembles
  - `async save(): Promise<void>` — sends save TLV to persist config to flash
  - `async reboot(): Promise<void>` — sends reboot TLV
  - `close(): void` — closes transport
  - Event emitter for `'error'`, `'timeout'`

### Phase 5: Index & Packaging (`index.ts`)

Barrel export:

```typescript
export { SwitchClient } from './client';
export { discoverSwitches } from './discovery';
export { encode, decode } from './cipher';
export * from './types';
```

---

## Technical Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Language | TypeScript | Matches the `tplink-switch-ui` React/TS stack, type safety for protocol parsing |
| Runtime | Node.js (dgram) | Native UDP support, cross-platform, no native deps |
| Module format | ESM + CJS dual build | Maximum compatibility |
| Build tool | tsup or tsc | Simple, no bundler complexity |
| Dependencies | Zero runtime deps | Only `dgram`, `os`, `buffer` from Node stdlib. Dev deps: vitest, typescript |
| MAC/IP resolution | `os.networkInterfaces()` | Avoids the `netifaces` native dependency that the Python implementations require |
| Buffer handling | Node.js `Buffer` | Native, fast, perfect for binary protocol work |
| Async model | Promises with async/await | Clean UDP socket wrapping with timeouts via `Promise.race` |

---

## Tests

### Unit Tests (no network required)

1. **Cipher round-trip**: `decode(encode(data))` should equal original data for various lengths
2. **Cipher known vector**: Encode a known plaintext packet and compare against expected ciphertext (capture from Wireshark or compute from Python reference)
3. **Header pack/unpack round-trip**: Create a header, pack it, unpack it, verify all fields match
4. **TLV pack/unpack round-trip**: Create TLV entries, pack, unpack, verify
5. **Full packet assembly**: Verify `checkLength` is correct, PACKET_END is appended
6. **Value parsers**: Test each parser (parseIp, parseMac, parseString, parseBool, parsePortConfig, parseVlan, parsePvid, parsePortStats) with known byte sequences
7. **Port bitmask helpers**: `portsToBitmask([1,3,5])` = `0b10101` = `21`, and back

### Integration Tests (requires a switch on the network, skip in CI)

1. Discovery finds at least one switch
2. Login succeeds with correct credentials
3. Login fails with wrong credentials (check error_code)
4. Get ports returns expected number of ports
5. Get/set VLAN round-trip
6. Get port statistics returns data
7. Get bandwidth ingress/egress returns rows for each port
8. Get storm control parses 9-byte rows on TL-SG1024DE v7.0
9. No-op writes on safe test ports round-trip without changing state
10. Cable test returns a typed result for a disconnected test port

### Live Validation Notes

Validated against a TL-SG1024DE hardware v7.0 at `192.168.99.5`, firmware `1.0.0 Build 20230616 Rel.34205`.

- Read-only calls passed for info, ports, VLANs, PVIDs, management VLAN, MTU VLAN, port VLAN mode, IGMP, QoS, bandwidth, storm control, mirror, loop prevention, port statistics, and full config.
- Safe no-op writes passed on ports 2 and 24 for port config, PVID, bandwidth egress, and storm control. Bandwidth ingress accepted a no-op write in isolated testing, but rapid reconnect/write loops can still expose UDP timeouts.
- Cable tests on disconnected ports 2 and 24 returned `open` at `1m`.
- PoE system read correctly reports unsupported/no data on this non-PoE model.

---

## Known Gotchas to Handle

1. **Broadcast sockets on Linux**: May need `SO_BROADCAST` and binding to `255.255.255.255` vs `0.0.0.0` — test both and document. On macOS, bind to `''` with `SO_REUSEADDR`.
2. **Fragmented responses**: Large responses (many VLANs, many ports) may come in multiple packets with non-zero `fragmentOffset`. Concatenate payloads before parsing TLVs.
3. **Token refresh before every SET**: Always do a GET with `get_token_id` before any LOGIN/SET operation. The `tokenId` from the response header must be stored and used in the next request.
4. **VLAN name corruption**: Never set multiple VLANs in a single SET packet. Always one VLAN per SET request (firmware bug documented by rgl).
5. **Null-terminated strings**: Username, password, VLAN names, hostname all require `\0` termination when sent to the switch.
6. **Receive own broadcast**: The receive socket may pick up the client's own outgoing broadcast. Filter by checking `opCode` in the response header — client sends GET(1)/LOGIN(3)/DISCOVERY(0), switch replies SET(2)/RETURN(4).
7. **Root/admin required**: Binding to privileged ports or using raw broadcast sockets may require elevated permissions on some OSes.
8. **Sequence ID correlation**: Match response `sequenceId` to the request to handle stale packets.
9. **Socket cleanup**: Always close sockets on error or when done. Use try/finally patterns.
10. **Port must belong to at least one VLAN**: Never remove a port from all VLANs. The Ansible collection handles this by putting undefined ports into VLAN 1.
11. **Avoid concurrent requests on one client**: The UDP transport now filters by request sequence ID, but high-level client calls should still be treated as a single in-flight request stream unless a request queue is added.
12. **Storm-control row length varies from older notes**: TL-SG1024DE v7.0 returns 9-byte rows with a 4-byte big-endian rate; tests should use that layout.
13. **Management IP writes can cut off access**: Changing DHCP/static IP or management VLAN affects reachability immediately. Read the current config and preserve fields unless intentionally changing them.
14. **PoE TLVs are model-dependent**: Non-PoE switches may return no TLVs for PoE reads. Callers should handle empty arrays or unsupported errors.

---

## Integration with tplink-switch-ui

This library is designed to be consumed by the `tplink-switch-ui` React/TypeScript dashboard. The intended integration pattern:

1. The UI project adds `tplink-escp` as a local dependency (or publish to git.vault.codes npm registry)
2. A thin Express/Fastify API server in the UI project wraps the `SwitchClient` calls as REST endpoints:
   - `GET /api/switches` → `discoverSwitches()`
   - `GET /api/switch/:mac/ports` → `client.getPorts()`
   - `GET /api/switch/:mac/vlans` → `client.getVlans()`
   - `POST /api/switch/:mac/vlans` → `client.setVlan()`
   - `GET /api/switch/:mac/stats` → `client.getPortStatistics()`
   - etc.
3. The API server manages `SwitchClient` instances per switch MAC (connection pooling/caching)
4. WebSocket support for polling port statistics at intervals

---

## Milestone Checklist

- [x] Phase 1: `cipher.ts`, `types.ts`, `protocol.ts` with unit tests passing
- [x] Phase 2: `transport.ts` with socket lifecycle management
- [x] Phase 3: `discovery.ts` working against a real switch
- [x] Phase 4: `client.ts` with get/set methods for the currently mapped TLVs
- [x] Phase 5: `index.ts` barrel exports, package.json, tsconfig, build working
- [x] All unit tests passing
- [x] Integration test against a real switch
- [ ] Commit and push.
