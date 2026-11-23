import {test} from 'node:test';
import assert from 'node:assert/strict';
import {fromBase64,toBase64,publicKeyOptions,credentialJSON,generatePassword} from '../src/auth.mjs';
import {validateRecord} from '../src/crypto.mjs';
test('binary passkey fields roundtrip without padding',()=>{
  const bytes=new Uint8Array([0,255,128,17]);
  assert.deepEqual(fromBase64(toBase64(bytes)),bytes);
  assert.throws(()=>fromBase64('../invalid'));
});
test('registration and authentication decode binary fields without mutating server data',()=>{
  const options={publicKey:{challenge:'AQID',user:{id:'BAUG'},excludeCredentials:[{id:'BwgJ',type:'public-key'}]}};
  const converted=publicKeyOptions(options,true);
  assert.deepEqual([...converted.publicKey.user.id],[4,5,6]);
  assert.equal(options.publicKey.challenge,'AQID');
  assert.deepEqual([...publicKeyOptions({publicKey:{challenge:'AQID',allowCredentials:[{id:'BAUG'}]}},false).publicKey.allowCredentials[0].id],[4,5,6]);
});
test('assertion serializes server-required extensions and nullable user handle',()=>{
  const buffer=new Uint8Array([1,2,3]).buffer;
  const value=credentialJSON({id:'AQID',rawId:buffer,type:'public-key',getClientExtensionResults:()=>({}),
    response:{clientDataJSON:buffer,authenticatorData:buffer,signature:buffer,userHandle:null}});
  assert.deepEqual(value.extensions,{});assert.equal(value.response.signature,'AQID');assert.equal(value.response.userHandle,null);
});
test('password generator rejects biased range and respects bounds',()=>{
  let calls=0;
  const random={getRandomValues(bytes){bytes.fill(++calls===1?255:0);}};
  assert.equal(generatePassword(24,random),'A'.repeat(24));assert.equal(calls,2);
  assert.throws(()=>generatePassword(15));assert.throws(()=>generatePassword(129));
  assert.notEqual(generatePassword(),generatePassword());
});
test('records reject unknown fields, overlong values, and missing titles',()=>{
  const record={title:'Example',username:'owner',password:'secret',url:'https://example.test',notes:''};
  assert.deepEqual(validateRecord(record),record);
  assert.throws(()=>validateRecord({...record,title:''}));
  assert.throws(()=>validateRecord({...record,password:'x'.repeat(4097)}));
  assert.throws(()=>validateRecord({...record,html:'<script>'}));
});
