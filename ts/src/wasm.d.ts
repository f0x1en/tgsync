// SPDX-License-Identifier: AGPL-3.0-or-later
// esbuild embeds .wasm files as bytes (--loader:.wasm=binary).
declare module "*.wasm" {
  const bytes: Uint8Array;
  export default bytes;
}
