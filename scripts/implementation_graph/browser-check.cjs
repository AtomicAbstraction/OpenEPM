#!/usr/bin/env node
// QA uses its own loopback server and disposable annotation file. It never
// touches owner edits, business services, containers or databases.
const assert=require('node:assert/strict'),fs=require('node:fs/promises'),path=require('node:path'),os=require('node:os'),{spawn}=require('node:child_process');
const [artifact,playwrightModule,browserExecutable]=process.argv.slice(2);
if(!artifact||!playwrightModule||!browserExecutable)throw Error('Usage: node browser-check.cjs ARTIFACT PLAYWRIGHT_MODULE CHROMIUM_EXECUTABLE');
const {chromium}=require(playwrightModule);
(async()=>{
 const temp=await fs.mkdtemp(path.join(os.tmpdir(),'openepm-graph-qa-')),state=path.join(temp,'annotations.json'),errors=[],network=[];
 let server,browser,url;
 const start=()=>new Promise((resolve,reject)=>{
  server=spawn(process.execPath,[path.join(__dirname,'server.mjs'),'--root',artifact,'--state',state,'--port','4359'],{stdio:['ignore','pipe','pipe']});
  let output='';server.stdout.on('data',d=>{output+=d;try{url=JSON.parse(output.trim()).url;resolve(url)}catch{}});server.stderr.on('data',d=>errors.push(String(d)));server.on('error',reject);server.on('exit',c=>{if(c)reject(Error('QA server exited '+c))});
 });
 const stop=()=>new Promise(resolve=>{if(!server||server.exitCode!==null)return resolve();server.once('exit',resolve);server.kill()});
 try{
  await start();
  browser=await chromium.launch({executablePath:browserExecutable,headless:true,args:['--use-angle=swiftshader','--enable-unsafe-swiftshader']});
  const page=await browser.newPage({viewport:{width:1600,height:1000}});
  page.on('pageerror',e=>errors.push(e.message));page.on('request',r=>{if(!r.url().startsWith(url)&&!r.url().startsWith('data:')&&!r.url().startsWith('blob:'))network.push(r.url())});
  await page.goto(url);await page.waitForFunction(()=>window.epmGraph?.getAuthorState().serverReady);await page.waitForTimeout(1500);
  assert.equal(await page.evaluate(()=>window.epmGraph.getState().webgl),true,'WebGL must render');
  assert.equal(await page.locator('#webgl-error').isVisible(),false);
  const dimensions=[];
  for(const [width,height]of [[1440,900],[1600,1000],[1920,1080],[2048,1320]]){
   await page.setViewportSize({width,height});await page.waitForTimeout(200);
   const m=await page.evaluate(()=>({width:innerWidth,height:innerHeight,scrollWidth:document.documentElement.scrollWidth,scrollHeight:document.documentElement.scrollHeight,canvas:document.querySelector('#graph canvas').width,labels:document.querySelectorAll('.node-label').length}));
   assert.ok(m.scrollWidth<=width&&m.scrollHeight<=height,JSON.stringify(m));assert.ok(m.canvas>100);dimensions.push(m);
  }
  await page.setViewportSize({width:1600,height:1000});await page.waitForTimeout(750);await page.screenshot({path:path.join(artifact,'overview.png')});
  await page.locator('#labels-button').click();await page.waitForFunction(()=>document.querySelectorAll('.node-label').length===0);
  await page.locator('#labels-button').click();await page.waitForFunction(()=>document.querySelectorAll('.node-label').length>0);
  const hoverBox=await page.locator('.node-label').first().boundingBox();await page.mouse.move(hoverBox.x+hoverBox.width/2,hoverBox.y+hoverBox.height/2);await page.locator('#hover-card.preview').waitFor({state:'visible'});
  const firstTitle=await page.locator('#hover-title').innerText();
  const next=await page.evaluate(title=>{const card=document.querySelector('#hover-card').getBoundingClientRect();for(const label of document.querySelectorAll('.node-label')){const r=label.getBoundingClientRect();if(label.textContent!==title&&(r.right<card.left||r.left>card.right||r.bottom<card.top||r.top>card.bottom))return {x:r.x+r.width/2,y:r.y+r.height/2,name:label.textContent}}},firstTitle);
  assert.ok(next,'Another node is reachable outside the compact hover preview');await page.mouse.move(next.x,next.y);await page.waitForFunction(name=>document.getElementById('hover-title').textContent===name,next.name);
  await page.mouse.move(50,200);await page.locator('#hover-card').waitFor({state:'hidden'});
  await page.mouse.move(hoverBox.x+hoverBox.width/2,hoverBox.y+hoverBox.height/2);await page.locator('#hover-card.preview').waitFor({state:'visible'});await page.locator('#pin-card').click();await page.mouse.move(50,200);await page.waitForTimeout(350);assert.ok(await page.locator('#hover-card').isVisible(),'Pinned editor stays open after leaving');await page.locator('#close-card').click();
  // UI controls drive the normal app. No business mutation endpoints exist.
  await page.locator('#search').fill('dimension');await page.locator('#search-results .search-result').first().waitFor();assert.ok(await page.locator('#search-results').innerText());
  await page.locator('#search').fill('');
  await page.locator('[data-function="functionality:metadata."]').click();
  assert.equal(await page.evaluate(()=>window.epmGraph.getState().focus),'functionality:metadata.');
  await page.selectOption('#detail','symbols');await page.waitForTimeout(400);assert.ok((await page.evaluate(()=>window.epmGraph.getState().visibleNodes))>10);
  await page.locator('#layers-button').click();await page.locator('[data-layer="Evidence"]').uncheck();await page.locator('[data-close="layers-dialog"]').click();assert.ok(!(await page.evaluate(()=>window.epmGraph.getState().layers)).includes('Evidence'));
  await page.locator('#edit-selected').click();await page.locator('#hover-card').waitFor({state:'visible'});
  const id=await page.evaluate(()=>window.epmGraph.getState().selected);
  const malicious='Owner summary <img src=x onerror="window.bad=true"> & scope';
  await page.locator('#edit-description').fill(malicious);
  await page.locator('#add-test').click();await page.getByLabel('Test name',{exact:true}).fill('Verify dimension lifecycle');
  await page.getByLabel('Test notes',{exact:true}).fill('Draft only. No executable or passing run is claimed.');
  await page.getByLabel('Test active status',{exact:true}).selectOption('Inactive');
  await page.locator('[data-add-comment]').click();await page.getByLabel('Comment 1',{exact:true}).fill('First comment: explicit scope');
  await page.locator('[data-add-comment]').click();await page.getByLabel('Comment 2',{exact:true}).fill('Second comment: preserve independently');
  await page.screenshot({path:path.join(artifact,'editor.png')});
  await page.locator('#save-card').click();await page.waitForFunction(()=>window.epmGraph.getAuthorState().dirty===false);
  const saved=JSON.parse(await fs.readFile(state,'utf8'));assert.equal(saved.nodes[id].description,malicious);assert.equal(saved.nodes[id].tests[0].status,'Inactive');assert.equal(saved.nodes[id].tests[0].comments.length,2);
  assert.equal(await page.evaluate(()=>window.bad),undefined);
  await page.locator('#close-card').click();await page.reload();await page.waitForFunction(()=>window.epmGraph?.getAuthorState().serverReady);
  await page.evaluate(id=>{window.epmGraph.choose(id);window.epmGraph.openCard(id,true)},id);
  assert.equal(await page.locator('#edit-description').inputValue(),malicious);assert.equal(await page.getByLabel('Test active status',{exact:true}).inputValue(),'Inactive');assert.equal(await page.getByLabel('Comment 2',{exact:true}).inputValue(),'Second comment: preserve independently');
  const downloadPromise=page.waitForEvent('download');await page.locator('#export-edits').click();const download=await downloadPromise;const exported=JSON.parse(await fs.readFile(await download.path(),'utf8'));assert.equal(exported.nodes[id].tests[0].comments.length,2);
  await page.getByLabel('Test active status',{exact:true}).selectOption('Active');await page.locator('#save-card').click();await page.waitForFunction(()=>!window.epmGraph.getAuthorState().dirty);
  // A changed snapshot key is an orphan, never reassigned to a similarly named
  // node. Import preserves the orphan and supports explicit export/reconcile.
  const imported=JSON.parse(await fs.readFile(state,'utf8'));imported.nodes['removed:qa-node']={description:'Retain for reconciliation',tests:[],hiddenGeneratedTests:[]};
  await page.locator('#import-file').setInputFiles({name:'edits.json',mimeType:'application/json',buffer:Buffer.from(JSON.stringify(imported))});
  await page.waitForFunction(()=>window.epmGraph.getAuthorState().orphans.length===1);await page.locator('#save-card').click();await page.waitForFunction(()=>!window.epmGraph.getAuthorState().dirty);
  await page.locator('#close-card').click();await page.evaluate(()=>window.epmGraph.choose('operation:metadata.dimension.create'));assert.match(await page.locator('#inspector').innerText(),/MCP/);
  await page.evaluate(()=>window.epmGraph.showSource('epm_core/postgres_metadata.py',1));assert.ok(await page.locator('#source-dialog').isVisible());await page.locator('[data-close="source-dialog"]').click();
  // The localhost endpoint rejects unrelated origins and stale-tab overwrite.
  const origin=new URL(url).origin;
  let r=await fetch(url+'/api/annotations',{method:'PUT',headers:{'Content-Type':'application/json','Origin':'https://unrelated.invalid','If-Match':'0'},body:JSON.stringify(saved)});assert.equal(r.status,403);
  r=await fetch(url+'/api/annotations',{method:'PUT',headers:{'Content-Type':'application/json','Origin':origin,'If-Match':'0'},body:JSON.stringify(saved)});assert.equal(r.status,409);
  r=await fetch(url+'/api/annotations',{method:'PUT',headers:{'Content-Type':'application/json','Origin':origin,'If-Match':'3'},body:JSON.stringify({format:'bad',nodes:{}})});assert.equal(r.status,400);
  r=await fetch(url+'/../PROJECT_INPUTS.md');assert.equal(r.status,404);
  const before=JSON.parse(await fs.readFile(state,'utf8'));
  await stop();await start();r=await fetch(url+'/api/annotations');const restarted=await r.json();assert.deepEqual(restarted.state.nodes,before.nodes);
  assert.deepEqual(errors,[]);assert.deepEqual(network,[]);
  const report={passed:true,url,artifactHash:JSON.parse(await fs.readFile(path.join(artifact,'receipt.json'),'utf8')).htmlSha256,viewports:dimensions,checks:['WebGL rendered','names off/on restores labels','compact hover follows nodes','hover closes on leave','pinned editor stays open','search/functionality/detail/layer controls','frozen source inspection','description escaping','Active/Inactive editing and retention','separate comment columns','metadata export/import','atomic disk save','page reload','server restart','orphan retention','cross-origin denial','stale-tab conflict','invalid metadata rejection','path allowlist','no remote requests'],temporaryMetadataOnly:true};
  await fs.writeFile(path.join(artifact,'browser-validation.json'),JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify(report,null,2));
 }finally{await browser?.close();await stop();await fs.rm(temp,{recursive:true,force:true})}
})().catch(e=>{console.error(e);process.exitCode=1});
