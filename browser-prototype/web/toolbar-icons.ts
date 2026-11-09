const paths={
 connect:'<path d="m9 5 10 7-10 7V5Z"/>',
 disconnect:'<rect x="6" y="6" width="12" height="12" rx="2"/>',
 keyboard:'<rect x="2" y="5" width="20" height="14" rx="3"/><path d="M6 9h.01M10 9h.01M14 9h.01M18 9h.01M6 12h.01M10 12h.01M14 12h.01M18 12h.01M8 15h8"/>',
 fullscreen:'<path d="M8 3H3v5m13-5h5v5M3 16v5h5m13-5v5h-5"/>',
 show:'<path d="m9 10 3 3 3-3"/><path d="M4 9h.01M4 13h.01M20 9h.01M20 13h.01"/>',
 hide:'<path d="m9 13 3-3 3 3"/><path d="M4 9h.01M4 13h.01M20 9h.01M20 13h.01"/>',
};
export function icon(name:keyof typeof paths){return `<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths[name]}</svg>`;}
export function setupToolbarIcons(){
 for(const [id,label] of [['connect','Connect'],['disconnect','Disconnect'],['keyboard','Keyboard'],['fullscreen','Fullscreen']] as const){
  const button=document.getElementById(id)!;button.innerHTML=icon(id);button.setAttribute('aria-label',label);button.title=label;button.classList.add('icon-button');
 }
}
