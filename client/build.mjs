import {createRequire} from 'node:module';
import {dirname, resolve} from 'node:path';
import {chmod, copyFile, cp, mkdir, readdir, rm} from 'node:fs/promises';
const require = createRequire(import.meta.url);
await rm(new URL('./dist', import.meta.url), {recursive:true, force:true});
await mkdir(new URL('./dist/vendor', import.meta.url), {recursive:true});
await cp(new URL('./src', import.meta.url), new URL('./dist', import.meta.url), {recursive:true});
// CommonJS distributions are also UMD browser scripts; load core before wrapper.
for (const [name, target] of [['libsodium-sumo','sodium-core.js'], ['libsodium-wrappers-sumo','sodium.js']]) {
  const source = require.resolve(name);
  await copyFile(source, new URL('./dist/vendor/'+target, import.meta.url));
  await copyFile(resolve(dirname(source),'../../LICENSE'), new URL('./dist/vendor/'+name+'.LICENSE', import.meta.url));
}

// Generated assets are public. npm may preserve 0600 package-file modes when
// installed under umask 077; the non-root proxy must still be able to read them.
async function publicAssets(directory) {
  await chmod(directory, 0o755);
  for (const entry of await readdir(directory, {withFileTypes:true})) {
    const target = new URL(entry.name + (entry.isDirectory() ? '/' : ''), directory);
    if (entry.isDirectory()) await publicAssets(target);
    else if (entry.isFile()) await chmod(target, 0o644);
    else throw Error('Unexpected asset type');
  }
}
await publicAssets(new URL('./dist/', import.meta.url));
