const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', {fatal:true});
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const kdf = Object.freeze({algorithm:'argon2id',version:19,memory_kib:65536,iterations:3,parallelism:1});
function id(value) { if (!uuid.test(value)) throw Error('Invalid identifier'); return value; }
function revision(value) { if (!Number.isSafeInteger(value) || value < 1) throw Error('Invalid revision'); return value; }
export function validateRecord(record) {
  if (!record || Object.keys(record).sort().join(',') !== 'notes,password,title,url,username') throw Error('Invalid entry');
  for (const [key,max] of Object.entries({title:256,username:1024,password:4096,url:2048,notes:8192})) {
    if (typeof record[key] !== 'string' || record[key].length > max) throw Error('Invalid entry');
  }
  if (!record.title.trim()) throw Error('A title is required');
  return record;
}
export function vaultCrypto(sodium) {
  const encode = value => sodium.to_base64(value, sodium.base64_variants.URLSAFE_NO_PADDING);
  function decode(value, min, max=min) {
    if (typeof value !== 'string' || value.length > Math.ceil(max*4/3)) throw Error('Invalid encrypted data');
    const bytes = sodium.from_base64(value, sodium.base64_variants.URLSAFE_NO_PADDING);
    if (bytes.length < min || bytes.length > max || encode(bytes) !== value) throw Error('Invalid encrypted data');
    return bytes;
  }
  // Separate domains bind wrapped keys and records to their owner/vault/entry/revision.
  const wrapAAD = (owner,vault,envelope) => encoder.encode(JSON.stringify(['private-vault',1,'key',id(owner),id(vault),envelope.kdf,envelope.salt]));
  const entryAAD = (owner,vault,entry,rev) => encoder.encode(JSON.stringify(['private-vault',1,'entry',id(owner),id(vault),id(entry),revision(rev)]));
  function parameters(envelope) {
    const p = envelope?.kdf;
    if (envelope?.version !== 1 || p?.algorithm !== 'argon2id' || p.version !== 19 ||
        ![65536,131072,262144].includes(p.memory_kib) || p.iterations !== 3 || p.parallelism !== 1 ||
        Object.keys(p).sort().join(',') !== Object.keys(kdf).sort().join(',')) throw Error('Unsupported encryption parameters');
    // Stable property order for authenticated metadata regardless of JSON input order.
    return {...envelope,kdf:{algorithm:p.algorithm,version:p.version,memory_kib:p.memory_kib,iterations:p.iterations,parallelism:p.parallelism}};
  }
  function derive(password,envelope) {
    if (typeof password !== 'string' || password.length < 1 || encoder.encode(password).length > 1024) throw Error('Invalid master password');
    const bytes = encoder.encode(password);
    try {
      return sodium.crypto_pwhash(32,bytes,decode(envelope.salt,16),envelope.kdf.iterations,
        envelope.kdf.memory_kib*1024,sodium.crypto_pwhash_ALG_ARGON2ID13);
    } finally { sodium.memzero(bytes); }
  }
  return {
    create(password,owner,vault) {
      if (typeof password !== 'string' || password.length < 16) throw Error('Use a master password of at least 16 characters');
      const envelope = {version:1,salt:encode(sodium.randombytes_buf(16)),nonce:encode(sodium.randombytes_buf(24)),kdf:{...kdf}};
      const wrapping = derive(password,envelope);
      const key = sodium.randombytes_buf(32);
      try {
        envelope.wrapped_key = encode(sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(key,wrapAAD(owner,vault,envelope),null,decode(envelope.nonce,24),wrapping));
        return {key,envelope};
      } catch (error) { sodium.memzero(key); throw error; }
      finally { sodium.memzero(wrapping); }
    },
    unlock(password,owner,vault,input) {
      const envelope = parameters(input);
      const ciphertext = decode(envelope.wrapped_key,48);
      const nonce = decode(envelope.nonce,24);
      const wrapping = derive(password,envelope);
      try { return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null,ciphertext,wrapAAD(owner,vault,envelope),nonce,wrapping); }
      finally { sodium.memzero(wrapping); }
    },
    encrypt(key,owner,vault,entry,rev,record) {
      const bytes = encoder.encode(JSON.stringify(validateRecord(record)));
      const nonce = sodium.randombytes_buf(24);
      if (bytes.length > 65520) { sodium.memzero(bytes); throw Error('Entry exceeds encrypted size limit'); }
      try { return {nonce:encode(nonce),ciphertext:encode(sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(bytes,entryAAD(owner,vault,entry,rev),null,nonce,key))}; }
      finally { sodium.memzero(bytes); }
    },
    decrypt(key,owner,vault,entry) {
      const bytes = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null,decode(entry.ciphertext,16,65536),entryAAD(owner,vault,entry.id,entry.revision),decode(entry.nonce,24),key);
      try { return validateRecord(JSON.parse(decoder.decode(bytes))); }
      finally { sodium.memzero(bytes); }
    }
  };
}
