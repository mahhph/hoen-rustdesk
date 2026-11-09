import {ConnectionRecovery} from './recovery.mjs';
import {isRetryable,toSessionError} from '../vendor/rdweb/src/connector';
import { displayControls } from './display-controls';
import {icon,setupToolbarIcons} from './toolbar-icons';
import {dockToolbar} from './toolbar-dock';

import type {SessionOptions} from '../vendor/rdweb/src/types';
import { Session } from '../vendor/rdweb/src/session';
import { Viewer } from '../vendor/rdweb/src/viewer';

const connect=document.querySelector<HTMLButtonElement>('#connect')!;
const computer=document.querySelector<HTMLSelectElement>('#computer')!;

const toolbar=document.querySelector<HTMLElement>('#toolbar')!;
const toolbarToggle=document.querySelector<HTMLButtonElement>('#toolbar-toggle')!;
setupToolbarIcons();
const updateDock=dockToolbar(toolbar,toolbarToggle);
function collapseToolbar(collapsed:boolean){
 toolbar.classList.toggle('collapsed',collapsed);
 toolbarToggle.innerHTML=icon(collapsed?'show':'hide');
 toolbarToggle.setAttribute('aria-expanded',String(!collapsed));
 toolbarToggle.setAttribute('aria-label',collapsed?'Show toolbar':'Hide toolbar');
 toolbarToggle.title=collapsed?'Show toolbar':'Hide toolbar';
 updateDock();
}
toolbarToggle.onclick=()=>collapseToolbar(!toolbar.classList.contains('collapsed'));
collapseToolbar(false);
const disconnect=document.querySelector<HTMLButtonElement>('#disconnect')!;
const status=document.querySelector<HTMLElement>('#status')!;
const area=document.querySelector<HTMLElement>('#viewer')!;
let session: Session | null=null;
let viewer: Viewer | null=null;
const keyboard=document.querySelector<HTMLButtonElement>('#keyboard')!;

const decode=(value:string)=>Uint8Array.from(atob(value.replace(/-/g,'+').replace(/_/g,'/').padEnd(Math.ceil(value.length/4)*4,'=')),c=>c.charCodeAt(0));
const hex=(bytes:Uint8Array)=>Array.from(bytes,b=>b.toString(16).padStart(2,'0')).join('');

let selectedHost='';
const signin=document.querySelector<HTMLAnchorElement>('#signin')!;
async function api(url:string,signal:AbortSignal,body?:unknown){
 const response=await fetch(url,{signal,...(body?{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}:{})});
 if(response.status===401){signin.hidden=false;throw new Error('Your website sign-in expired. Sign in again.');}
 if(!response.ok)throw Object.assign(new Error(response.status>=500?'The desktop service is unavailable.':'The connection request was rejected.'),{retryable:response.status>=500});
 return response.json();
}
const recovery=new ConnectionRecovery(({signal,active,connected,closed}:{signal:AbortSignal;active:()=>boolean;connected:()=>void;closed:(message:string,retryable:boolean)=>void})=>{
 let localSession:Session|null=null,localViewer:Viewer|null=null;
 void (async()=>{
  try{
   const config=await api('/api/config?host='+encodeURIComponent(selectedHost),signal);if(!active())return;
   if(!/^[0-9a-f]{64}$/i.test(config.hostFingerprint))throw new Error('Invalid host identity. Connection stopped.');
   const fingerprint=new Uint8Array(config.hostFingerprint.match(/../g).map((x:string)=>parseInt(x,16)));
   const gatewayUrl=`${location.protocol==='https:'?'wss:':'ws:'}//${location.host}/desktop?host=${encodeURIComponent(config.host)}`;
   const options:SessionOptions={peerId:config.host,server:{rendezvousUrl:'',key:''},hoen:{gatewayUrl,hostFingerprint:fingerprint,issueProof:async(host,binding)=>{
    const p=await api('/api/proof',signal,{host,binding:hex(binding)});return {viewerKey:decode(p.viewerKey),grantToken:decode(p.grantToken),signature:decode(p.signature)};
   }}};
   localSession=new Session(options);session=localSession;localViewer=new Viewer(area,localSession);viewer=localViewer;displayControls(localSession,localViewer);
   localSession.on('connected',()=>{if(active()){localViewer?.focus();connected();}});
   localSession.on('close',info=>closed(info.reason,info.retryable));
   await localSession.connect();
  }catch(error){if(!active())return;const e=error as Error&{retryable?:boolean};closed(e.message||'Connection failed.',e.retryable===true||error instanceof TypeError||isRetryable(toSessionError(error)));}
 })();
 return()=>{localSession?.close();localViewer?.destroy();if(session===localSession)session=null;if(viewer===localViewer)viewer=null;document.querySelector<HTMLElement>('#display-controls')!.hidden=true;};
},({phase,message}:{phase:string;message:string})=>{
 const busy=['connecting','waiting','connected'].includes(phase);
 connect.disabled=busy||!computer.options.length;computer.disabled=busy;disconnect.disabled=!busy;keyboard.disabled=phase!=='connected';
 disconnect.title=phase==='connected'?'Disconnect':'Cancel connection';disconnect.setAttribute('aria-label',disconnect.title);
 status.textContent=message;collapseToolbar(phase==='connected');
});
connect.addEventListener('click',()=>{selectedHost=computer.value;signin.hidden=true;recovery.start();});
disconnect.addEventListener('click',()=>recovery.stop());
async function loadMachines(){
 try{const c=await api('/api/machines',AbortSignal.timeout(10000));computer.replaceChildren(...c.machines.map((m:{host:string;displayName:string})=>new Option(m.displayName,m.host)));status.textContent='';connect.disabled=!c.machines.length;computer.disabled=false;document.querySelector<HTMLButtonElement>('#reload-computers')!.hidden=true;}
 catch(error){status.textContent=error instanceof Error?error.message:'Could not load computers.';document.querySelector<HTMLButtonElement>('#reload-computers')!.hidden=false;}
}
document.querySelector<HTMLButtonElement>('#reload-computers')!.onclick=()=>void loadMachines();
void loadMachines();
keyboard.addEventListener('click',()=>viewer?.showKeyboard());
const viewport=window.visualViewport;
function fitViewport(){const height=viewport?.height??window.innerHeight;area.style.height=`${height}px`;document.documentElement.style.setProperty('--visible-height',`${height}px`);updateDock();}
viewport?.addEventListener('resize',fitViewport);window.addEventListener('resize',fitViewport);fitViewport();

