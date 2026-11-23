import {publicKeyOptions,credentialJSON,generatePassword} from './auth.mjs';
const $ = id => document.getElementById(id);
let session, vault, editing, worker, serial=0, generation=0, pending=new Map(), busy=false;
const form = $('entry-form');
const status = text => {$('status').textContent=text;};
function clearEditor() {
  form.reset(); form.elements.password.type='password'; $('reveal').textContent='Show password';
  editing=undefined; $('editor-title').textContent='New entry';
}
function lock() {
  generation++;
  worker?.terminate(); worker=undefined;
  for (const item of pending.values()) item.reject(Error('Vault locked'));
  pending.clear();
  $('entries').replaceChildren(); clearEditor(); $('master').value=''; $('confirm').value='';
  $('unlocked').hidden=true; $('unlock-form').hidden=false;
}
function rpc(operation,data={}) {
  if (!worker) {
    worker = new Worker('/worker.js');
    worker.onmessage=({data})=>{
      if (data.locked) {lock();status('Vault locked.');return;}
      const item=pending.get(data.id); if (!item) return;
      pending.delete(data.id);
      if (data.error) {item.reject(Error('Could not unlock or authenticate encrypted data.')); lock();}
      else item.resolve(data.result);
    };
    worker.onerror=()=>{lock();status('Encryption worker failed. Vault locked.');};
  }
  return new Promise((resolve,reject)=>{
    const id=++serial;pending.set(id,{resolve,reject});worker.postMessage({id,operation,...data});
  });
}
async function request(path,method='GET',body) {
  const headers={}; if (body !== undefined) headers['Content-Type']='application/json';
  if (session && method !== 'GET') headers['X-CSRF-Token']=session.csrf_token;
  const response=await fetch('/api/v1/'+path,{method,headers,credentials:'same-origin',cache:'no-store',redirect:'error',
    signal:AbortSignal.timeout(15000),body:body===undefined?undefined:JSON.stringify(body)});
  if (!response.ok) {
    if (response.status===401) {lock();session=undefined;$('signed-in').hidden=true;$('signed-out').hidden=false;}
    const error=Error(response.status===409?'This entry changed. Refresh before saving again.':
      response.status===429?'Too many requests. Wait a minute before trying again.':
      response.status===403?'Sign in again before this operation.': 'Request failed ('+response.status+').');
    error.status=response.status;throw error;
  }
  return response.status===204 || response.status===201 ? undefined : response.json();
}
async function ceremony(kind,body) {
  const register=kind!=='login';
  const {options}=await request('auth/'+kind+'/begin','POST',body);
  const parsed=publicKeyOptions(options,register);
  const credential=register?await navigator.credentials.create(parsed):await navigator.credentials.get(parsed);
  if (!credential) throw Error('Passkey operation canceled');
  return request('auth/'+kind+'/finish','POST',credentialJSON(credential));
}
function configureVaultForm() {
  const create=!vault;
  $('unlock-heading').textContent=create?'Create your vault':'Unlock vault';
  $('unlock-submit').textContent=create?'Create vault':'Unlock';
  $('confirm-label').hidden=!create;$('confirm').required=create;
}
async function loadSession() {
  session=await request('auth/session');
  $('signed-out').hidden=true;$('signed-in').hidden=false;lock();
  try {vault=await request('vault');}
  catch(error) {if(error.status!==404) throw error;vault=undefined;}
  configureVaultForm();
  status(!vault?'Choose a unique master password of at least 16 characters.':'Signed in. Unlock with your master password.');
}
async function list() {
  const current=generation;
  const nodes=[];let after='';let count=0;
  do {
    const rows=await request('entries?limit=100'+(after?'&after='+after:''));
    for (const row of rows) {
      if (++count>10000) throw Error('Entry limit exceeded');
      if (row.deleted) continue;
      const record=await rpc('decrypt',{entry:row});
      if (generation!==current) return;
      const li=document.createElement('li');
      const edit=document.createElement('button');edit.textContent=record.title;
      // Keep only IDs/revisions in handlers; decrypt again when editing.
      edit.onclick=()=>run(async()=>{
        const fresh=await request('entries/'+row.id);
        const value=await rpc('decrypt',{entry:fresh});
        if(generation!==current)return;
        clearEditor();editing={id:row.id,revision:fresh.revision};
        for(const field of ['title','username','password','url','notes']) form.elements[field].value=value[field];
        $('editor-title').textContent='Edit entry';
      });
      const remove=document.createElement('button');remove.textContent='Delete';
      remove.onclick=()=>run(async()=>{
        if(!confirm('Delete this entry?'))return;
        await request('entries/'+row.id,'DELETE',{expected_revision:row.revision});
        clearEditor();await list();status('Entry deleted.');
      });
      li.append(edit,remove);nodes.push(li);
    }
    if(generation!==current)return;
    if(rows.length<100)break;
    const next=rows.at(-1).id;
    if(next<=after)throw Error('Invalid pagination');
    after=next;
  } while(true);
  if(generation===current)$('entries').replaceChildren(...nodes);
}
async function run(action) {
  if(busy)return;busy=true;
  for(const button of document.querySelectorAll('button'))button.disabled=button.id!=='lock';
  try {await action();}
  catch(error) {status(error.name==='NotAllowedError'?'Passkey operation canceled or unavailable.':error.message);}
  finally {busy=false;for(const button of document.querySelectorAll('button'))button.disabled=false;}
}
$('login').onclick=()=>run(async()=>{await ceremony('login');await loadSession();});
$('enroll-form').onsubmit=event=>{event.preventDefault();run(async()=>{
  const token=$('token').value;$('token').value='';
  await ceremony('bootstrap',{enrollment_token:token});status('Passkey enrolled. Sign in to continue.');
});};
$('add-passkey').onclick=()=>run(async()=>{lock();await ceremony('register');status('Additional passkey enrolled.');});
$('unlock-form').onsubmit=event=>{event.preventDefault();run(async()=>{
  const password=$('master').value;const confirmation=$('confirm').value;
  $('master').value='';$('confirm').value='';
  if(!vault&&password!==confirmation)throw Error('Master passwords do not match');
  const current=generation;
  if(!vault) {
    const id=crypto.randomUUID();
    const envelope=await rpc('create',{password,owner:session.owner,vault:id});
    if(generation!==current)return;
    try {await request('vault','PUT',{id,expected_revision:0,envelope});vault=await request('vault');configureVaultForm();}
    catch(error){lock();throw error;}
  } else await rpc('unlock',{password,owner:session.owner,vault:vault.id,envelope:vault.envelope});
  if(generation!==current)return;
  $('unlock-form').hidden=true;$('unlocked').hidden=false;
  await list();status('Vault unlocked.');
});};
$('entry-form').onsubmit=event=>{event.preventDefault();run(async()=>{
  const current=generation;
  const record=Object.fromEntries(['title','username','password','url','notes'].map(name=>[name,form.elements[name].value]));
  const id=editing?.id??crypto.randomUUID();const expected=editing?.revision??0;
  const encrypted=await rpc('encrypt',{entry:id,revision:expected+1,record});
  if(generation!==current)return;
  await request('entries/'+id,'PUT',{expected_revision:expected,...encrypted});
  clearEditor();await list();status('Encrypted entry saved.');
});};
$('generate').onclick=()=>{form.elements.password.value=generatePassword();};
$('reveal').onclick=()=>{const show=form.elements.password.type==='password';form.elements.password.type=show?'text':'password';$('reveal').textContent=show?'Hide password':'Show password';};
$('cancel').onclick=clearEditor;
$('refresh').onclick=()=>run(list);
$('lock').onclick=()=>{lock();status('Vault locked.');};
$('logout').onclick=()=>{lock();run(async()=>{
  await request('auth/logout','POST');session=undefined;vault=undefined;
  $('signed-in').hidden=true;$('signed-out').hidden=false;status('Signed out.');
});};
document.addEventListener('visibilitychange',()=>{if(document.hidden){lock();status('Vault locked.');}});
window.addEventListener('pagehide',lock);
if (!window.isSecureContext || !navigator.credentials || !window.Worker) status('A trusted HTTPS connection and a browser supporting passkeys and workers are required.');
else run(async()=>{try{await loadSession();}catch(error){if(error.status!==401)throw error;status('Sign in with your passkey.');}});
