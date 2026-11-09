export class ConnectionRecovery {
 constructor(connect,report,{delays=[1000,2000,4000],timeout=30000,stable=30000}={}){Object.assign(this,{connect,report,delays,timeout,stable});this.generation=0;this.wanted=false;this.retries=0;this.timers=[];}
 clear(){this.generation++;for(const t of this.timers)clearTimeout(t);this.timers=[];this.abort?.abort();const cleanup=this.cleanup;this.cleanup=null;cleanup?.();}
 start(){this.clear();this.wanted=true;this.retries=0;this.attempt();}
 stop(){this.wanted=false;this.clear();this.report({phase:'stopped',message:'Disconnected'});}
 attempt(){
  this.clear();if(!this.wanted)return;
  const generation=this.generation,active=()=>this.wanted&&generation===this.generation;
  this.abort=new AbortController();this.report({phase:'connecting',message:this.retries?'Reconnecting…':'Connecting…'});
  const fail=(message,retryable=true)=>{
   if(!active())return;this.clear();
   if(retryable&&this.retries<this.delays.length){const delay=this.delays[this.retries++];this.report({phase:'waiting',message:`${message} Retrying in ${delay/1000}s (${this.retries}/${this.delays.length}).`});this.timers.push(setTimeout(()=>this.attempt(),delay));}
   else{this.wanted=false;this.report({phase:'failed',message});}
  };
  const deadline=setTimeout(()=>fail('Connection timed out.',true),this.timeout);this.timers.push(deadline);
  try{
   const cleanup=this.connect({signal:this.abort.signal,active,connected:()=>{if(!active())return;clearTimeout(deadline);this.report({phase:'connected',message:'Connected'});this.timers.push(setTimeout(()=>{if(active())this.retries=0;},this.stable));},closed:fail});
   if(active())this.cleanup=cleanup;else cleanup?.();
  }catch(error){fail(error instanceof Error?error.message:'Connection failed.',false);}
 }
}
