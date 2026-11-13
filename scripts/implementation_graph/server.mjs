#!/usr/bin/env node
// Local graph-authoring server. No application credentials, business APIs,
// source mutation, test execution, remote binding or runtime dependencies.
import http from 'node:http';
import fs from 'node:fs/promises';
import path from 'node:path';
import {randomUUID} from 'node:crypto';

const args=process.argv.slice(2),opts={};
for(let i=0;i<args.length;i+=2){if(!['--root','--state','--port'].includes(args[i])||!args[i+1])throw Error('Use --root ARTIFACT --state ANNOTATIONS_FILE [--port 4319]');opts[args[i]]=args[i+1]}
if(!opts['--root']||!opts['--state'])throw Error('--root and --state are required');
const root=path.resolve(opts['--root']),statePath=path.resolve(opts['--state']);
let port=Number(opts['--port']||4319),queue=Promise.resolve();
if(!Number.isInteger(port)||port<1024||port>65515)throw Error('Invalid port');
await fs.access(path.join(root,'index.html'));
const initial={format:'openepm-graph-annotations-v1',revision:0,nodes:{}};
await fs.mkdir(path.dirname(statePath),{recursive:true});
try{await fs.writeFile(statePath,JSON.stringify(initial,null,2)+'\n',{flag:'wx',mode:0o600})}catch(e){if(e.code!=='EEXIST')throw e}

export function validate(data){
 if(!data||typeof data!=='object'||Array.isArray(data)||data.format!=='openepm-graph-annotations-v1')throw Error('Invalid annotation format');
 if(!data.nodes||typeof data.nodes!=='object'||Array.isArray(data.nodes)||Object.keys(data.nodes).length>20000)throw Error('Invalid annotation nodes');
 const validString=(s,max,required=false)=>typeof s==='string'&&s.length<=max&&(!required||s.length>0);
 for(const [id,row]of Object.entries(data.nodes)){
  if(!validString(id,2000,true)||['__proto__','prototype','constructor'].includes(id)||!row||typeof row!=='object'||Array.isArray(row))throw Error('Invalid node identity');
  if(!validString(row.description??'',12000)||!Array.isArray(row.tests??[])||(row.tests??[]).length>200)throw Error('Invalid node description/tests');
  if(!Array.isArray(row.hiddenGeneratedTests??[])||!(row.hiddenGeneratedTests??[]).every(x=>validString(x,2000)))throw Error('Invalid hidden association list');
  const ids=new Set();
  for(const test of row.tests??[]){
   if(!test||!validString(test.id,200,true)||ids.has(test.id)||!validString(test.name,300,true)||!['draft specification','existing executable association'].includes(test.kind)||!['Active','Inactive'].includes(test.status)||!validString(test.notes??'',12000)||!validString(test.path??'',2000))throw Error('Invalid test record');
   ids.add(test.id);
   if(!Array.isArray(test.entireRefs??[])||(test.entireRefs??[]).length>20||!(test.entireRefs??[]).every(id=>validString(id,4000,true)))throw Error('Invalid attached Entire references');
   if(!Array.isArray(test.comments??[])||(test.comments??[]).length>500)throw Error('Invalid comments');
   const commentIds=new Set();for(const c of test.comments??[]){if(!c||!validString(c.id,200,true)||commentIds.has(c.id)||!validString(c.text,12000))throw Error('Invalid individual comment');commentIds.add(c.id)}
  }
 }
 return data;
}
const readState=async()=>validate(JSON.parse(await fs.readFile(statePath,'utf8')));
const reply=(res,status,data,headers={})=>{const body=typeof data==='string'?data:JSON.stringify(data);res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','X-Content-Type-Options':'nosniff','Cache-Control':'no-store',...headers});res.end(body)};
const server=http.createServer(async(req,res)=>{
 try{
  const hosts=new Set([`127.0.0.1:${port}`,`localhost:${port}`]);
  if(!hosts.has(req.headers.host)){reply(res,403,{error:'Loopback host required'});return}
  const url=new URL(req.url,`http://127.0.0.1:${port}`);
  if(url.pathname==='/api/annotations'){
   if(req.method==='GET'){const state=await readState();reply(res,200,{state,revision:state.revision??0},{ETag:String(state.revision??0)});return}
   if(req.method!=='PUT'){reply(res,405,{error:'Use GET or PUT'});return}
   if(!new Set([`http://127.0.0.1:${port}`,`http://localhost:${port}`]).has(req.headers.origin)){reply(res,403,{error:'Same-origin local authoring required'});return}
   if(!req.headers['content-type']?.startsWith('application/json')){reply(res,415,{error:'JSON required'});return}
   if(req.headers['if-match']===undefined){reply(res,428,{error:'Revision required; reload before saving'});return}
   const chunks=[];let bytes=0;for await(const chunk of req){bytes+=chunk.length;if(bytes>4*1024*1024){reply(res,413,{error:'Metadata too large'});return}chunks.push(chunk)}
   let data;try{data=validate(JSON.parse(Buffer.concat(chunks).toString('utf8')))}catch(e){reply(res,400,{error:e.message});return}
   // Serialize compare-and-swap and atomic replacement across simultaneous tabs.
   queue=queue.catch(()=>{}).then(async()=>{
    const current=await readState(),revision=current.revision??0;
    if(req.headers['if-match']!==String(revision)){reply(res,409,{error:'Another tab saved changes. Export your edits, then reload/import to reconcile.',revision});return}
    const next={...data,revision:revision+1,savedAt:new Date().toISOString()},tmp=statePath+'.'+randomUUID()+'.tmp';
    const handle=await fs.open(tmp,'wx',0o600);
    try{await handle.writeFile(JSON.stringify(next,null,2)+'\n');await handle.sync()}finally{await handle.close()}
    try{await fs.rename(tmp,statePath);const dir=await fs.open(path.dirname(statePath),'r');try{await dir.sync()}finally{await dir.close()}}catch(e){await fs.rm(tmp,{force:true});throw e}
    reply(res,200,{state:next,revision:next.revision});
   });await queue;return;
  }
  if(req.method!=='GET'&&req.method!=='HEAD'){reply(res,405,{error:'Read only artifact route'});return}
  const name=url.pathname==='/'?'index.html':url.pathname.slice(1);
  const allowed=new Set(['index.html','graph.json','coverage.json','receipt.json','LICENSE-3d-force-graph.txt','source-manifest.json']);
  if(!allowed.has(name)){reply(res,404,{error:'Not found'});return}
  const bytes=await fs.readFile(path.join(root,name));
  res.writeHead(200,{'Content-Type':name.endsWith('.html')?'text/html; charset=utf-8':name.endsWith('.json')?'application/json; charset=utf-8':'text/plain; charset=utf-8','X-Content-Type-Options':'nosniff','Cache-Control':'no-store','Content-Length':bytes.length,'Referrer-Policy':'no-referrer'});
  res.end(req.method==='HEAD'?undefined:bytes);
 }catch(e){if(!res.headersSent)reply(res,500,{error:'Local graph request failed'});else res.end();console.error(e.message)}
});
let attempts=0;
server.on('error',e=>{if(e.code==='EADDRINUSE'&&attempts++<20){port++;server.listen(port,'127.0.0.1')}else{console.error(e.message);process.exitCode=1}});
server.on('listening',()=>console.log(JSON.stringify({url:`http://127.0.0.1:${port}`,artifact:root,metadata:statePath,pid:process.pid})));
server.listen(port,'127.0.0.1');
