import {test} from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {readdir,stat} from 'node:fs/promises';
test('a restrictive install umask still produces assets readable by the non-root proxy',async()=>{
  const previous=process.umask(0o077);
  let result;
  try { result=spawnSync(process.execPath,['build.mjs'],{cwd:new URL('../',import.meta.url),encoding:'utf8'}); }
  finally { process.umask(previous); }
  assert.equal(result.status,0,result.stderr);
  const root=new URL('../dist/',import.meta.url);
  async function inspect(directory) {
    assert.equal((await stat(directory)).mode & 0o777,0o755);
    for(const entry of await readdir(directory,{withFileTypes:true})) {
      const target=new URL(entry.name+(entry.isDirectory()?'/':''),directory);
      if(entry.isDirectory())await inspect(target);
      else assert.equal((await stat(target)).mode & 0o777,0o644,entry.name);
    }
  }
  await inspect(root);
});
