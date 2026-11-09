import { displayControls } from './display-controls';

import type {SessionOptions} from '../vendor/rdweb/src/types';
import { Session } from '../vendor/rdweb/src/session';
import { Viewer } from '../vendor/rdweb/src/viewer';

const connect=document.querySelector<HTMLButtonElement>('#connect')!;
const computer=document.querySelector<HTMLSelectElement>('#computer')!;

const toolbar=document.querySelector<HTMLElement>('#toolbar')!;
const toolbarToggle=document.querySelector<HTMLButtonElement>('#toolbar-toggle')!;
function collapseToolbar(collapsed:boolean){
 toolbar.classList.toggle('collapsed',collapsed);
 toolbarToggle.textContent=collapsed?'⌄ Menu':'⌃ Hide';
 toolbarToggle.setAttribute('aria-expanded',String(!collapsed));
 toolbarToggle.setAttribute('aria-label',collapsed?'Show toolbar':'Hide toolbar');
 toolbarToggle.title=collapsed?'Show toolbar':'Hide toolbar';
}
toolbarToggle.onclick=()=>collapseToolbar(!toolbar.classList.contains('collapsed'));
const disconnect=document.querySelector<HTMLButtonElement>('#disconnect')!;
const status=document.querySelector<HTMLElement>('#status')!;
const area=document.querySelector<HTMLElement>('#viewer')!;
let session: Session | null=null;
let viewer: Viewer | null=null;
const keyboard=document.querySelector<HTMLButtonElement>('#keyboard')!;

const decode=(value:string)=>Uint8Array.from(atob(value.replace(/-/g,'+').replace(/_/g,'/').padEnd(Math.ceil(value.length/4)*4,'=')),c=>c.charCodeAt(0));
const hex=(bytes:Uint8Array)=>Array.from(bytes,b=>b.toString(16).padStart(2,'0')).join('');

async function start() {
  connect.disabled=true;computer.disabled=true;
  try {
    const response=await fetch('/api/config?host='+encodeURIComponent(computer.value));
    if(!response.ok)throw new Error('The prototype viewer has not been configured yet.');
    const config=await response.json();
    if(!/^[0-9a-f]{64}$/i.test(config.hostFingerprint))throw new Error('Invalid host configuration.');
    const fingerprint=new Uint8Array(config.hostFingerprint.match(/../g).map((x:string)=>parseInt(x,16)));
    const gatewayUrl=`${location.protocol==='https:'?'wss:':'ws:'}//${location.host}/desktop?host=${encodeURIComponent(config.host)}`;
    const options:SessionOptions={peerId:config.host,server:{rendezvousUrl:'',key:''},hoen:{gatewayUrl,hostFingerprint:fingerprint,issueProof:async(host,binding)=>{
      const reply=await fetch('/api/proof',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({host,binding:hex(binding)})});
      if(!reply.ok)throw new Error('Could not obtain a desktop connection proof.');
      const p=await reply.json();return {viewerKey:decode(p.viewerKey),grantToken:decode(p.grantToken),signature:decode(p.signature)};
    }}};
    session=new Session(options);

    viewer?.destroy(); viewer=new Viewer(area,session); displayControls(session,viewer);
    session.on('state',({state})=>{status.textContent=state==='connected'?'Connected':`Connecting: ${state}`;});
    session.on('connected',()=>{status.textContent='Connected';disconnect.disabled=false;viewer?.focus();keyboard.disabled=false;collapseToolbar(true);});
    session.on('close',({reason})=>{status.textContent=`Disconnected: ${reason}`;disconnect.disabled=true;keyboard.disabled=true;computer.disabled=false;viewer?.destroy();viewer=null;connect.disabled=false;collapseToolbar(false);});
    await session.connect();
  } catch(error) { status.textContent=error instanceof Error?error.message:'Connection failed.'; session?.close(); session=null;connect.disabled=false;computer.disabled=false; }
}
connect.addEventListener('click',()=>void start());
disconnect.addEventListener('click',()=>{session?.close();session=null;disconnect.disabled=true;keyboard.disabled=true;viewer?.destroy();viewer=null;connect.disabled=false;status.textContent='Disconnected';});
fetch('/api/machines').then(r=>{if(!r.ok)throw new Error();return r.json();}).then(c=>{computer.replaceChildren(...c.machines.map((m:{host:string;displayName:string})=>new Option(m.displayName,m.host)));status.textContent='Choose a computer and connect';connect.disabled=!c.machines.length;computer.disabled=false;}).catch(()=>{status.textContent='Could not load registered computers.';});

keyboard.addEventListener('click',()=>viewer?.showKeyboard());


