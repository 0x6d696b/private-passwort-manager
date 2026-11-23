import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {readFile} from 'node:fs/promises';
import vm from 'node:vm';
const require=createRequire(import.meta.url);
test('UMD browser distributions initialize without CommonJS or a CDN',async()=>{
  const context=vm.createContext({crypto,WebAssembly,TextEncoder,TextDecoder,Uint8Array,ArrayBuffer,
    setTimeout,clearTimeout,console,atob,btoa});
  context.self=context;
  for(const name of ['libsodium-sumo','libsodium-wrappers-sumo']) {
    const source=await readFile(require.resolve(name),'utf8');
    vm.runInContext(source,context,{timeout:10000});
  }
  await context.sodium.ready;
  assert.equal(context.sodium.randombytes_buf(24).length,24);
  assert.equal(typeof context.sodium.crypto_pwhash,'function');
  assert.equal(typeof context.sodium.crypto_aead_xchacha20poly1305_ietf_encrypt,'function');
});
