// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// Runs test binaries built for wasm32-unknown-unknown under Node:
//
//   cargo test --no-run --target wasm32-unknown-unknown
//   node scripts/run_wasm_tests.mjs target/wasm32-unknown-unknown/debug/deps/*.wasm
//
// Each module must import nothing: rustc links wasm with --allow-undefined, so a C symbol
// that nothing defines becomes an import instead of a link error. Rust's test harness
// runs every test in `main`; the target aborts on panic, so a failing test is a trap.

import { readFileSync } from 'node:fs';
import { basename } from 'node:path';

const paths = process.argv.slice(2);
if (paths.length === 0) {
  console.error('usage: run_wasm_tests.mjs <test binary>.wasm...');
  process.exit(2);
}

// Returns why the binary failed, or null if every test in it passed.
function failure(path) {
  const module = new WebAssembly.Module(readFileSync(path));
  const imports = WebAssembly.Module.imports(module).map((i) => `${i.module}.${i.name}`);
  if (imports.length !== 0) return `unexpected imports: ${imports.join(', ')}`;
  const { main } = new WebAssembly.Instance(module, {}).exports;
  if (typeof main !== 'function') return 'no exported main; is this a test binary?';
  try {
    const code = main(0, 0);
    return code === 0 ? null : `main returned ${code}`;
  } catch (error) {
    return `a test panicked (${error})`;
  }
}

let failed = false;
for (const path of paths) {
  const why = failure(path);
  console.log(`${basename(path)}: ${why === null ? 'ok' : `FAILED, ${why}`}`);
  failed ||= why !== null;
}
process.exit(failed ? 1 : 0);
