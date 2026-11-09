import type {Session} from '../vendor/rdweb/src/session';
import type {Viewer} from '../vendor/rdweb/src/viewer';
export function displayControls(session:Session,viewer:Viewer){
 const panel=document.querySelector<HTMLElement>('#display-controls')!;
 const monitor=panel.querySelector<HTMLSelectElement>('#monitor')!;
 const resolution=panel.querySelector<HTMLSelectElement>('#resolution')!;
 const scale=panel.querySelector<HTMLSelectElement>('#scale')!;
 const notice=panel.querySelector<HTMLElement>('#display-notice')!;
 const apply=panel.querySelector<HTMLButtonElement>('#apply-resolution')!;
 const fullscreen=panel.querySelector<HTMLButtonElement>('#fullscreen')!;
 let timeout:ReturnType<typeof setTimeout>|undefined;
 const refresh=()=>{
  const peer=session.peer,display=session.display;if(!peer||!display)return;
  monitor.replaceChildren(...peer.displays.filter(d=>d.online).map(d=>new Option(`Monitor ${d.index+1} · ${d.width}×${d.height}`,String(d.index))));monitor.value=String(display.index);
  const options=peer.resolutions.filter(r=>r.width>0&&r.height>0);
  resolution.replaceChildren(new Option(`${display.width}×${display.height} (current)`,'current'),...options.filter(r=>r.width!==display.width||r.height!==display.height).map(r=>new Option(`${r.width}×${r.height}`,`${r.width}x${r.height}`)),new Option('Restore original resolution','0x0'));
  apply.disabled=true;panel.hidden=false;
 };
 monitor.onchange=()=>{notice.textContent='Switching monitor…';session.switchDisplay(Number(monitor.value));};
 resolution.onchange=()=>{apply.disabled=resolution.value==='current';};
 apply.onclick=()=>{const [w,h]=resolution.value.split('x').map(Number);if(!Number.isInteger(w)||!Number.isInteger(h))return;session.changeResolution(w,h);notice.textContent='Requested resolution change on the host monitor…';apply.disabled=true;clearTimeout(timeout);timeout=setTimeout(()=>{notice.textContent='No display update received. The host may not support this resolution.';apply.disabled=resolution.value==='current';},10000);};
 scale.onchange=()=>{viewer.setScaleMode(scale.value==='original'?'original':'fit');viewer.focus();};
 fullscreen.onclick=async()=>{try{if(document.fullscreenElement)await document.exitFullscreen();else await document.documentElement.requestFullscreen();}catch{notice.textContent='Fullscreen is unavailable in this browser. Try landscape orientation.';}};
 scale.value='fit';notice.textContent='Resolution changes affect the host monitor. Pinch to zoom on touchscreens.';
 const offConnected=session.on('connected',refresh);
 const offDisplay=session.on('display',()=>{clearTimeout(timeout);refresh();notice.textContent='Display updated.';});
 const offClose=session.on('close',()=>{clearTimeout(timeout);panel.hidden=true;offConnected();offDisplay();offClose();});
}
