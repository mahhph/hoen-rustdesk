// Independent Node conformance check; server authorization/transactions are tested by the server.
const {readFileSync}=require('node:fs');
const {isIP}=require('node:net');
const assert=require('node:assert/strict');
const cases=JSON.parse(readFileSync(require('node:path').join(__dirname,'../contracts/lan-v2/wire-cases.json')));
const max=Number.MAX_SAFE_INTEGER;
const fields=(o,keys)=>o!==null&&typeof o==='object'&&!Array.isArray(o)&&Object.keys(o).every(k=>keys.includes(k));
const counter=(n,min=0)=>Number.isSafeInteger(n)&&n>=min&&n<=max;
function endpoint(e){
 if(!fields(e,['address','port'])||!Number.isInteger(e.port)||e.port<1||e.port>65535||typeof e.address!=='string'||e.address.includes('%'))return false;
 const family=isIP(e.address);
 if(family===4){const a=e.address.split('.').map(Number);return e.address!=='0.0.0.0'&&e.address!=='255.255.255.255'&&a[0]!==127&&!(a[0]>=224&&a[0]<=239);}
 if(family===6){const host=new URL(`http://[${e.address}]/`).hostname.slice(1,-1);return host!=='::'&&host!=='::1'&&!host.startsWith('ff');}
 return false;
}
const errors=['invalid_request','unsupported_version','alias_conflict','identity_conflict','lease_superseded','sequence_stale','sequence_conflict','upgrade_required','host_offline','host_disabled','mailbox_unreachable','certificate_invalid','broker_unavailable','permission_missing','listener_bind_failed','history_delayed'];
function validate(kind,b){
 if(Buffer.byteLength(JSON.stringify(b))>4096)return false;
 if(kind==='registration')return fields(b,['alias','role','publicKeyFingerprint','endpoint'])&&typeof b.alias==='string'&&/^[\x20-\x7e]{1,64}$/.test(b.alias)&&b.alias.trim()===b.alias&&typeof b.publicKeyFingerprint==='string'&&/^[a-f0-9]{64}$/.test(b.publicKeyFingerprint)&&((b.role==='client'&&b.endpoint==null)||(['host','both'].includes(b.role)&&endpoint(b.endpoint)));
 if(kind==='leaseCreate')return fields(b,['requestId','expectedGeneration'])&&typeof b.requestId==='string'&&/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(b.requestId)&&counter(b.expectedGeneration)&&b.expectedGeneration<max;
 if(kind==='heartbeat')return fields(b,['generation','sequence','endpoint','listenerReady','capabilityReady','buildId','errorCode'])&&counter(b.generation,1)&&counter(b.sequence,1)&&(b.endpoint==null||endpoint(b.endpoint))&&typeof b.listenerReady==='boolean'&&typeof b.capabilityReady==='boolean'&&(!b.listenerReady||b.endpoint!=null)&&(!b.capabilityReady||b.listenerReady)&&typeof b.buildId==='string'&&/^[a-zA-Z0-9._-]{1,64}$/.test(b.buildId)&&(b.errorCode==null||errors.includes(b.errorCode));
 throw Error('Unknown fixture kind');
}
function validateRaw(kind,raw){
 try {
  if(Buffer.byteLength(raw)>4096)return false;
  const value=JSON.parse(raw);
  // All numeric fields in this protocol use unsigned decimal integer syntax.
  const unquoted=raw.replace(/"(?:\\.|[^"\\])*"/g,'""');
  const numbers=unquoted.match(/-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/g)||[];
  if(numbers.some(n=>!/^(?:0|[1-9]\d*)$/.test(n)))return false;
  return validate(kind,value);
 }catch{return false;}
}
for(const c of cases)assert.equal(validateRaw(c.kind,c.raw??JSON.stringify(c.body)),c.valid,c.name);
console.log(`Passed ${cases.length} LAN wire cases in Node`);
