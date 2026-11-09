type Edge='top'|'right'|'bottom'|'left';
export function dockToolbar(toolbar:HTMLElement,handle:HTMLButtonElement){
 let edge:Edge='top',fraction=.5;
 let start:{id:number;x:number;y:number}|null=null,dragging=false,suppressClick=false;
 const clamp=(n:number,min:number,max:number)=>Math.min(Math.max(min,max),Math.max(min,n));
 const place=()=>{
  const w=toolbar.offsetWidth,h=toolbar.offsetHeight,vw=window.visualViewport?.width??window.innerWidth,vh=window.visualViewport?.height??window.innerHeight;
  const x=edge==='left'?0:edge==='right'?vw-w:clamp(fraction*vw-w/2,0,vw-w);
  const y=edge==='top'?0:edge==='bottom'?vh-h:clamp(fraction*vh-h/2,0,vh-h);
  toolbar.style.left=`${Math.max(0,x)}px`;toolbar.style.top=`${Math.max(0,y)}px`;toolbar.style.transform='none';toolbar.dataset.edge=edge;
 };
 handle.style.touchAction='none';
 handle.addEventListener('pointerdown',e=>{if(!toolbar.classList.contains('collapsed')||e.button!==0)return;start={id:e.pointerId,x:e.clientX,y:e.clientY};dragging=false;suppressClick=false;handle.setPointerCapture(e.pointerId);});
 handle.addEventListener('pointermove',e=>{
  if(!start||start.id!==e.pointerId)return;
  if(!dragging&&Math.hypot(e.clientX-start.x,e.clientY-start.y)<6)return;
  dragging=true;const vw=window.visualViewport?.width??window.innerWidth,vh=window.visualViewport?.height??window.innerHeight;
  const distances:[Edge,number][]=[['top',e.clientY],['right',vw-e.clientX],['bottom',vh-e.clientY],['left',e.clientX]];
  edge=distances.sort((a,b)=>a[1]-b[1])[0][0];
  fraction=clamp(edge==='top'||edge==='bottom'?e.clientX/vw:e.clientY/vh,0,1);place();e.preventDefault();
 });
 const finish=(e:PointerEvent)=>{if(!start||e.pointerId!==start.id)return;suppressClick=dragging;start=null;dragging=false;if(handle.hasPointerCapture(e.pointerId))handle.releasePointerCapture(e.pointerId);};
 handle.addEventListener('pointerup',finish);handle.addEventListener('pointercancel',finish);
 handle.addEventListener('click',e=>{if(suppressClick){e.preventDefault();e.stopImmediatePropagation();suppressClick=false;}},true);
 handle.addEventListener('keydown',e=>{if(!toolbar.classList.contains('collapsed')||!['ArrowLeft','ArrowRight','ArrowUp','ArrowDown'].includes(e.key))return;e.preventDefault();fraction=clamp(fraction+(['ArrowLeft','ArrowUp'].includes(e.key)?-.03:.03),0,1);place();});
 window.addEventListener('resize',place);new ResizeObserver(place).observe(toolbar);place();
 return place;
}
