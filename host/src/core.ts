// SPDX-License-Identifier: AGPL-3.0-or-later
// The Rust core (core/), compiled to WebAssembly and embedded in the bundle (esbuild --loader:.wasm=binary).
// Build it with `make wasm` (or fetch CI's build with `scripts/fetch-wasm.sh`).
import * as w from "../../core/pkg-web/tgsync_wasm.js";
import bytes from "../../core/pkg-web/tgsync_wasm_bg.wasm";

w.initSync({ module: bytes });

export { w };
