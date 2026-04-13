# tplink-escp

TypeScript library for the TP-Link Easy Smart Configuration Protocol (ESCP).
Cross-platform Node.js replacement for the Windows-only Java Easy Smart Configuration Utility.

Supports TL-SG105E / SG108E / SG116E / SG1016DE / SG1024DE / SG108PE and similar.

## Install

```bash
npm install tplink-escp
```

## Discover switches

```ts
import { discoverSwitches } from 'tplink-escp';

const switches = await discoverSwitches({ timeout: 2000 });
for (const s of switches) {
  console.log(s.info.hostname, s.info.mac, s.info.ipAddress);
}
```

## Read and modify config

```ts
import { SwitchClient } from 'tplink-escp';

const client = new SwitchClient({
  switchMac: '00:11:22:33:44:55',
  username: 'admin',
  password: 'adminpass',
});

await client.login();
const info = await client.getInfo();
const ports = await client.getPorts();
const vlans = await client.getVlans();

// VLANs must be set one-at-a-time (firmware bug).
await client.setVlan({
  vlanId: 10,
  name: 'office',
  memberPorts: [1, 2, 3],
  taggedPorts: [1],
  untaggedPorts: [2, 3],
});

await client.save();
client.close();
```

## Notes

- UDP broadcast on ports 29808/29809. May require elevated permissions on some OSes.
- Encryption: RC4-variant with a hardcoded key shipped in every firmware — this is not security.
- Set VLANs one at a time to avoid corrupted VLAN names.
- Always leave every port in at least one VLAN.

## Build

```bash
npm install
npm run build
npm test
```
