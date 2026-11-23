export function fromBase64(value) {
  if (typeof value !== 'string' || value.length > 16384 || !/^[A-Za-z0-9_-]+$/.test(value)) throw Error('Invalid passkey data');
  return Uint8Array.from(atob(value.replaceAll('-','+').replaceAll('_','/')), c=>c.charCodeAt(0));
}
export function toBase64(value) {
  return btoa(String.fromCharCode(...new Uint8Array(value))).replaceAll('+','-').replaceAll('/','_').replaceAll('=','');
}
export function publicKeyOptions(options,register) {
  const p = structuredClone(options.publicKey);
  p.challenge = fromBase64(p.challenge);
  if (register) p.user.id = fromBase64(p.user.id);
  for (const name of ['allowCredentials','excludeCredentials']) {
    if (p[name]) p[name] = p[name].map(c=>({...c,id:fromBase64(c.id)}));
  }
  return {publicKey:p};
}
export function credentialJSON(credential) {
  const r = credential.response;
  const response = {clientDataJSON:toBase64(r.clientDataJSON)};
  if (r.attestationObject) {
    response.attestationObject = toBase64(r.attestationObject);
    response.transports = r.getTransports?.() ?? [];
  } else {
    response.authenticatorData = toBase64(r.authenticatorData);
    response.signature = toBase64(r.signature);
    response.userHandle = r.userHandle ? toBase64(r.userHandle) : null;
  }
  return {id:credential.id,rawId:toBase64(credential.rawId),type:credential.type,
    response,extensions:credential.getClientExtensionResults()};
}
export function generatePassword(length=24,random=crypto) {
  if (!Number.isInteger(length) || length < 16 || length > 128) throw Error('Invalid password length');
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,-./:;<=>?@[]^_{|}~';
  const limit = 256 - (256 % alphabet.length);
  let result='';
  const bytes = new Uint8Array(128);
  while (result.length < length) {
    random.getRandomValues(bytes);
    for (const value of bytes) if (value < limit && result.length < length) result += alphabet[value % alphabet.length];
  }
  bytes.fill(0);
  return result;
}
