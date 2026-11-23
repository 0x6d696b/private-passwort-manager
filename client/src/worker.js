importScripts('./vendor/sodium-core.js', './vendor/sodium.js');
let key, owner, vault, timer;
let queue = Promise.resolve();
function lock() {
  if (key) sodium.memzero(key);
  key = owner = vault = undefined;
  clearTimeout(timer);
}
const ready = Promise.all([sodium.ready,import('./crypto.mjs')]).then(([,module]) => module.vaultCrypto(sodium));
onmessage = ({data}) => {
  queue = queue.then(async () => {
    try {
      const crypto = await ready;
      let result;
      if (data.operation === 'lock') { lock(); }
      else if (data.operation === 'create' || data.operation === 'unlock') {
        lock();
        owner = data.owner; vault = data.vault;
        if (data.operation === 'create') {
          const created = crypto.create(data.password,owner,vault);
          key = created.key; result = created.envelope;
        } else key = crypto.unlock(data.password,owner,vault,data.envelope);
        // Absolute five-minute unlock lifetime, independent of activity messages.
        timer = setTimeout(() => {lock(); postMessage({locked:true});},300000);
      } else {
        if (!key) throw Error('Vault locked');
        if (data.operation === 'encrypt') result = crypto.encrypt(key,owner,vault,data.entry,data.revision,data.record);
        else if (data.operation === 'decrypt') result = crypto.decrypt(key,owner,vault,data.entry);
        else throw Error('Unknown operation');
      }
      postMessage({id:data.id,result});
    } catch { lock(); postMessage({id:data.id,error:true}); }
  });
};
