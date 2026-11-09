import type {Session} from '../vendor/rdweb/src/session';
import type {Viewer} from '../vendor/rdweb/src/viewer';
export function displayControls(session:Session,viewer:Viewer){
 const panel=document.querySelector<HTMLElement>('#display-controls')!;
 const scale=panel.querySelector<HTMLSelectElement>('#scale')!;
 const notice=panel.querySelector<HTMLElement>('#display-notice')!;
 const fullscreen=panel.querySelector<HTMLButtonElement>('#fullscreen')!;
 const input=panel.querySelector<HTMLSelectElement>('#input-mode')!;
 input.value=viewer.getInputMode();
 input.onchange=()=>{viewer.setInputMode(input.value==='touch'?'touch':input.value==='trackpad'?'trackpad':'mouse');notice.textContent=input.value==='trackpad'?'Slide to move the pointer; tap to click; two fingers to scroll or pinch to zoom.':input.value==='touch'?'Tap where you want to click; pinch to zoom.':'';};
 for(const button of panel.querySelectorAll<HTMLButtonElement>('[data-key]'))button.onclick=()=>{const code=button.dataset.key!,key=code==='Space'?' ':code;session.key({code,key,down:true});session.key({code,key,down:false});};
 scale.value='original';viewer.setScaleMode('original');notice.textContent='';
 scale.onchange=()=>{viewer.setScaleMode(scale.value==='original'?'original':'fit');viewer.focus();};
 fullscreen.onclick=async()=>{try{if(document.fullscreenElement)await document.exitFullscreen();else await document.documentElement.requestFullscreen();}catch{notice.textContent='Fullscreen is unavailable in this browser. Try landscape orientation.';}};
 const offConnected=session.on('connected',()=>{viewer.setScaleMode('original');panel.hidden=false;});
 const offClose=session.on('close',()=>{panel.hidden=true;offConnected();offClose();});
}
