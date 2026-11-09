import {FileTransferSession} from '../vendor/rdweb/src/files/session';
import type {SessionOptions} from '../vendor/rdweb/src/types';
export async function openFiles(options:SessionOptions){
 if(document.querySelector('#file-dialog'))return;
 const dialog=document.createElement('dialog');dialog.id='file-dialog';
 dialog.innerHTML='<h2>Files</h2><p>Paste or drop files here to copy them into the displayed remote folder. Use Download to copy a remote file to this device.</p><label>Remote folder <input id="remote-folder"></label><button id="open-folder">Open</button><button id="home-folder">Home</button><label>Upload files <input id="upload-files" type="file" multiple disabled></label><p id="file-status" role="status">Connecting…</p><div id="file-list"></div><button id="close-files">Close</button>';
 document.body.append(dialog);dialog.showModal();
 const ft=new FileTransferSession({...options,myName:'Browser file transfer'});
 const status=dialog.querySelector<HTMLElement>('#file-status')!,input=dialog.querySelector<HTMLInputElement>('#remote-folder')!,upload=dialog.querySelector<HTMLInputElement>('#upload-files')!,list=dialog.querySelector<HTMLElement>('#file-list')!;
 let cwd='',ready=false;
 const fail=(e:unknown)=>{status.textContent=e instanceof Error&&/connection lost/.test(e.message)?'This host requires an update for mailbox-authenticated file transfers.':e instanceof Error?e.message:'File transfer failed';};
 async function open(path:string){const dir=await ft.listDir(path);cwd=dir.path;input.value=cwd;list.replaceChildren();for(const entry of dir.entries){const row=document.createElement('div');row.className='file-row';const name=document.createElement('span');name.textContent=entry.name;const action=document.createElement('button');const isDir=['dir','dirLink','drive'].includes(entry.type);action.textContent=isDir?'Open':'Download';action.onclick=async()=>{try{const full=ft.joinPath(cwd,entry.name);if(isDir)await open(full);else{status.textContent='Downloading…';const {blob}=await ft.downloadBlob(full,{maxBytes:64*1024*1024});const url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download=entry.name;a.click();setTimeout(()=>URL.revokeObjectURL(url),60000);status.textContent='Download ready';}}catch(e){fail(e);}};row.append(name,action);list.append(row);}status.textContent=`${dir.entries.length} items`;}
 async function copy(files:File[]){if(!ready||!files.length)return;upload.disabled=true;try{status.textContent='Copying files…';await ft.upload(files,cwd,{overwrite:'skip'}).done;await open(cwd);status.textContent='Copy complete. Existing files were skipped.';}catch(e){fail(e);}finally{upload.disabled=false;upload.value='';}}
 upload.onchange=()=>void copy(Array.from(upload.files||[]));
 dialog.addEventListener('paste',e=>{const files=Array.from(e.clipboardData?.files||[]);if(files.length){e.preventDefault();void copy(files);}});
 dialog.addEventListener('dragover',e=>e.preventDefault());dialog.addEventListener('drop',e=>{e.preventDefault();void copy(Array.from(e.dataTransfer?.files||[]));});
 dialog.querySelector<HTMLButtonElement>('#open-folder')!.onclick=()=>void open(input.value).catch(fail);
 dialog.querySelector<HTMLButtonElement>('#home-folder')!.onclick=()=>void open('').catch(fail);
 dialog.querySelector<HTMLButtonElement>('#close-files')!.onclick=()=>dialog.close();
 dialog.onclose=()=>{ready=false;ft.close();dialog.remove();};
 try{await ft.connect();if(!dialog.isConnected)return;await open('');ready=true;upload.disabled=false;}catch(e){fail(e);}
}

