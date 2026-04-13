export { SwitchClient } from './client.js';
export { discoverSwitches } from './discovery.js';
export { encode, decode } from './cipher.js';
export * from './types.js';
export {
  assemblePacket,
  splitPacket,
  packHeader,
  unpackHeader,
  packTlvs,
  unpackTlvs,
  portsToBitmask,
  bitmaskToPorts,
  HEADER_LENGTH,
  PACKET_END,
} from './protocol.js';
