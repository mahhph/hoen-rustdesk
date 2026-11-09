import { Session } from '../vendor/rdweb/src/session';
import { Viewer } from '../vendor/rdweb/src/viewer';

const connect=document.querySelector<HTMLButtonElement>('#connect')!;
const disconnect=document.querySelector<HTMLButtonElement>('#disconnect')!;
const status=document.querySelector<HTMLElement>('#status')!;
const area=document.querySelector<HTMLElement>('#viewer')!;
let session: Session | null=null;
let viewer: Viewer | null=null;
const keyboard=document.querySelector<HTMLButtonElement>('#keyboard')!;

const decode=(value:string)=>Uint8Array.from(atob(value.replace(/-/g,'+').replace(/_/g,'/').padEnd(Math.ceil(value.length/4)*4,'=')),c=>c.charCodeAt(0));
const hex=(bytes:Uint8Array)=>Array.from(bytes,b=>b.toString(16).padStart(2,'0')).join('');

async function start() {
  connect.disabled=true;
  try {
    const response=await fetch('/api/config');
    if(!response.ok)throw new Error('The prototype viewer has not been configured yet.');
    const config=await response.json();
    if(!/^[0-9a-f]{64}$/i.test(config.hostFingerprint))throw new Error('Invalid host configuration.');
    const fingerprint=new Uint8Array(config.hostFingerprint.match(/../g).map((x:string)=>parseInt(x,16)));
    const gatewayUrl=`${location.protocol==='https:'?'wss:':'ws:'}//${location.host}/desktop`;
    session=new Session({peerId:config.host,server:{rendezvousUrl:'',key:''},hoen:{gatewayUrl,hostFingerprint:fingerprint,issueProof:async(host,binding)=>{
      const reply=await fetch('/api/proof',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({host,binding:hex(binding)})});
      if(!reply.ok)throw new Error('Could not obtain a desktop connection proof.');
      const p=await reply.json();return {viewerKey:decode(p.viewerKey),grantToken:decode(p.grantToken),signature:decode(p.signature)};
    }}});
    viewer?.destroy(); viewer=new Viewer(area,session);
    session.on('state',({state})=>{status.textContent=state==='connected'?'Connected':`Connecting: ${state}`;});
    session.on('connected',()=>{status.textContent='Connected';disconnect.disabled=false;viewer?.focus();keyboard.disabled=false;});
    session.on('close',({reason})=>{status.textContent=`Disconnected: ${reason}`;disconnect.disabled=true;keyboard.disabled=true;viewer?.destroy();viewer=null;connect.disabled=false;});
    await session.connect();
  } catch(error) { status.textContent=error instanceof Error?error.message:'Connection failed.'; session?.close(); session=null;connect.disabled=false; }
}
connect.addEventListener('click',()=>void start());
disconnect.addEventListener('click',()=>{session?.close();session=null;disconnect.disabled=true;keyboard.disabled=true;viewer?.destroy();viewer=null;connect.disabled=false;status.textContent='Disconnected';});
fetch('/api/config').then(r=>{if(!r.ok)throw new Error();return r.json();}).then(c=>{status.textContent=`Ready to connect to ${c.host}`;connect.disabled=false;}).catch(()=>{status.textContent='Prototype viewer is not configured yet.';});

keyboard.addEventListener('click',()=>viewer?.showKeyboard());
