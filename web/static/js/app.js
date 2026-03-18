/**
 * DorkMaster v8 -- Unified Frontend
 * Generator + Hunter (FREE/PREMIUM) + Scanner + Settings
 * Features: custom param builder, engine status, debug log, improved progress
 */
(function(){
'use strict';

let currentEngine='google', allDorks=[], filteredDorks=[], selectedRows=new Set();
let engineConfig=null, sortAsc=true;
let huntUrls=[], huntFiltered=[], isHunting=false, huntSearchMode='free';
let scanReport=null, scanFiltered=[], isScanning=false;
let currentMode='generator';
let quotaData=null;
let showDebugLog=false;

const $=s=>document.querySelector(s);
const $$=s=>document.querySelectorAll(s);
const el={};

const RENDER_LIMIT=500;

function cache(){
    ['kwInput','kwFileUpload','kwClear','kwCount','opGrid','opCount','opAll','opNone',
     'ftGrid','ftCount','ftAll','ftNone','vpGrid','vpCount','vpAll','vpNone','vpCatList',
     'siteInput','exclInput','useQuotes','genAll',
     'maxResults','maxGroup','genBtn','genSearch','genSort','genShuffle','genEmpty',
     'genList','genResCount','genBody','copyAll','copySel','expTxt','expCsv','expJson',
     'sendHunt','sendScan','statPossibleVal','statGeneratedVal','statPossible','statGenerated',
     'overlay','overlayTitle','overlaySub',
     'huntDorks','huntDorkCount','huntFileUpload','huntClearDorks','huntEngines',
     'huntPages','huntConc','huntDelayMin','huntDelayMax',
     'huntBtn','huntSearch','huntUrlCount','huntEmpty','huntList',
     'huntBody','huntCopyAll','huntExpTxt','huntExpCsv','huntExpJson','huntProgress',
     'huntProgressFill','huntProgressText','huntProgressNum','sendUrlsToScan',
     'huntModeCardFree','huntModeCardApi','huntUseProxy','huntFreeEnginesCard',
     'quotaBarHunter','quotaFillHunter','quotaTextHunter','quotaRemHunter',
     'engineStatusBar','debugLog','debugLogBody','clearLog','toggleLog',
     'paramFileType','paramCustomType','paramName','paramPreview','paramPreviewUrl',
     'paramPreviewDorks','paramAddBtn',
     'scanUrls','scanUrlCount','scanFileUpload','scanClearUrls','scanSqli','scanXss',
     'scanConc','scanTimeout','scanRate','scanBtn','scanSearch','scanResCount',
     'scanEmpty','scanList','scanBody','scanProgress','scanProgressFill','scanProgressText',
     'scanProgressNum','scanSummary','sumUrls','sumFindings','sumSqli','sumXss',
     'scanCopyFindings','scanExpTxt','scanExpCsv','scanExpJson','scanUseProxy',
     'setSerperKeys','saveKeysBtn','setProxyOn','setProxies','proxyFileUpload',
     'testProxiesBtn','saveProxiesBtn','proxyTestBox','proxyTestSummary','proxyTestList',
     'saveWorkingBtn','stSerper','stProxy','stProxyCount',
     'quotaBadge','quotaCapacity','quotaUsed','quotaRemaining','quotaFillSettings',
     'quotaKeyList','resetQuotaBtn','quotaOverview'
    ].forEach(id=>{el[id]=document.getElementById(id)});
}

async function init(){
    cache();
    try{
        const r=await fetch('/api/config');
        if(!r.ok)throw new Error('HTTP '+r.status);
        engineConfig=await r.json();
    }catch(e){toast('Failed to load config','err');return}
    setupNav();setupEngine();renderOps();renderFt();renderVulnParams();
    bindGen();bindParamBuilder();bindHunt();bindScan();bindSettings();
    updateCounts();syncGenAll();loadStatus();
}

/* -- Nav -- */
function setupNav(){
    $$('.nav-tab').forEach(t=>t.addEventListener('click',()=>switchMode(t.dataset.mode)));
}
function switchMode(m){
    currentMode=m;
    $$('.nav-tab').forEach(t=>t.classList.toggle('nav-tab--active',t.dataset.mode===m));
    $$('.mode').forEach(c=>c.classList.remove('mode--active'));
    const mEl=$('#mode'+m.charAt(0).toUpperCase()+m.slice(1));
    if(mEl)mEl.classList.add('mode--active');
    const show=m==='generator';
    if(el.statPossible)el.statPossible.style.display=show?'':'none';
    if(el.statGenerated)el.statGenerated.style.display=show?'':'none';
    if(m==='settings')loadStatus();
    if(m==='hunter')updateHuntQuotaBar();
}

/* -- Generator -- */
function setupEngine(){
    $$('.engine-opt').forEach(o=>{
        o.addEventListener('click',()=>{
            $$('.engine-opt').forEach(x=>x.classList.remove('engine-opt--on'));
            o.classList.add('engine-opt--on');
            currentEngine=o.dataset.engine;
            o.querySelector('input').checked=true;
            renderOps();renderFt();renderVulnParams();updateCounts();updateParamPreview();
        });
    });
}
function renderOps(){
    const eng=engineConfig?.engines?.[currentEngine];
    if(!eng||!el.opGrid)return;
    el.opGrid.innerHTML='';
    Object.keys(eng.operators).forEach(k=>{
        const c=document.createElement('button');c.type='button';
        c.className='chip';c.dataset.operator=k;c.textContent=k+':';
        c.title=eng.operators[k].description||k;
        c.addEventListener('click',()=>{c.classList.toggle('chip--on');updateCounts()});
        el.opGrid.appendChild(c);
    });
}
function renderFt(){
    const eng=engineConfig?.engines?.[currentEngine];
    if(!eng||!el.ftGrid)return;
    el.ftGrid.innerHTML='';
    (eng.filetypes||[]).forEach(f=>{
        const c=document.createElement('button');c.type='button';
        c.className='chip';c.dataset.filetype=f;c.textContent='.'+f;
        c.addEventListener('click',()=>{c.classList.toggle('chip--on');updateCounts()});
        el.ftGrid.appendChild(c);
    });
}
function renderVulnParams(){
    const vp=engineConfig?.vuln_params;
    if(!vp||!el.vpGrid)return;
    el.vpGrid.innerHTML='';
    const generic=vp.patterns?.generic||[];
    generic.forEach(p=>{
        const c=document.createElement('button');c.type='button';
        c.className='chip';c.dataset.vulnparam=p;c.textContent=p;
        c.addEventListener('click',()=>{c.classList.toggle('chip--on');updateVpCount()});
        el.vpGrid.appendChild(c);
    });
    updateVpCount();
    if(el.vpCatList){
        el.vpCatList.innerHTML='';
        const cats=vp.patterns||{};
        Object.keys(cats).forEach(cat=>{
            if(cat==='generic')return;
            const btn=document.createElement('button');
            btn.className='preset-chip';
            btn.innerHTML=`${cat.toUpperCase()} <span class="badge badge--sm">${cats[cat].length}</span>`;
            btn.addEventListener('click',()=>{
                cats[cat].forEach(p=>{
                    const existing=el.vpGrid.querySelector(`[data-vulnparam="${CSS.escape(p)}"]`);
                    if(!existing){
                        const c=document.createElement('button');c.type='button';
                        c.className='chip chip--on';c.dataset.vulnparam=p;c.textContent=p;
                        c.addEventListener('click',()=>{c.classList.toggle('chip--on');updateVpCount()});
                        el.vpGrid.appendChild(c);
                    }else{existing.classList.add('chip--on')}
                });
                updateVpCount();toast('Added '+cats[cat].length+' '+cat+' patterns');
            });
            el.vpCatList.appendChild(btn);
        });
    }
}
function updateVpCount(){if(el.vpCount)el.vpCount.textContent=getVps().length}
function getVps(){return el.vpGrid?[...el.vpGrid.querySelectorAll('.chip--on')].map(c=>c.dataset.vulnparam):[]}

/* -- Custom Param Builder -- */
function bindParamBuilder(){
    const inputs=[el.paramFileType,el.paramCustomType,el.paramName];
    inputs.forEach(inp=>{if(inp)inp.addEventListener('input',updateParamPreview)});
    if(el.paramFileType)el.paramFileType.addEventListener('change',updateParamPreview);

    // Preset param buttons
    $$('.param-preset').forEach(btn=>{
        btn.addEventListener('click',()=>{
            if(el.paramName)el.paramName.value=btn.dataset.param;
            updateParamPreview();
        });
    });

    if(el.paramAddBtn)el.paramAddBtn.addEventListener('click',addCustomParam);
}
function getFileType(){
    const custom=el.paramCustomType?.value.trim();
    if(custom){
        return custom.startsWith('.')?custom:'.'+custom;
    }
    return el.paramFileType?.value||'.php';
}
function updateParamPreview(){
    const ft=getFileType();
    const param=el.paramName?.value.trim();
    if(!param){hideEl(el.paramPreview);return}

    const pattern=`${ft}?${param}=`;
    showEl(el.paramPreview);
    if(el.paramPreviewUrl){
        el.paramPreviewUrl.textContent=`example${pattern}`;
    }

    // Show engine-specific dorks
    const syntax=engineConfig?.engine_dork_syntax||{};
    if(el.paramPreviewDorks){
        el.paramPreviewDorks.innerHTML='';
        Object.entries(syntax).forEach(([eng,info])=>{
            const div=document.createElement('div');
            div.className='param-preview__dork';
            let dork;
            if(info.supports_inurl){
                dork=info.inurl_syntax.replace('{pattern}',pattern);
            }else{
                dork=`"${pattern}"`;
            }
            div.innerHTML=`<span class="param-preview__dork-engine">${eng}</span><span class="param-preview__dork-text">${esc(dork)}</span>`;
            el.paramPreviewDorks.appendChild(div);
        });
    }
}
function addCustomParam(){
    const ft=getFileType();
    const param=el.paramName?.value.trim();
    if(!param){toast('Enter a parameter name','warn');return}

    const pattern=`${ft}?${param}=`;

    // Add to vuln params grid
    if(el.vpGrid){
        const existing=el.vpGrid.querySelector(`[data-vulnparam="${CSS.escape(pattern)}"]`);
        if(existing){
            existing.classList.add('chip--on');
            toast('Pattern already exists, activated');
        }else{
            const c=document.createElement('button');c.type='button';
            c.className='chip chip--on';c.dataset.vulnparam=pattern;c.textContent=pattern;
            c.addEventListener('click',()=>{c.classList.toggle('chip--on');updateVpCount()});
            el.vpGrid.appendChild(c);
            toast(`Added: ${pattern}`);
        }
        updateVpCount();updateCounts();
    }
}

function bindGen(){
    el.genBtn?.addEventListener('click',generate);
    el.kwInput?.addEventListener('input',updateCounts);
    el.kwFileUpload?.addEventListener('change',e=>fileUpload(e,el.kwInput,()=>updateCounts()));
    el.kwClear?.addEventListener('click',()=>{if(el.kwInput)el.kwInput.value='';updateCounts()});
    $$('.preset-chip').forEach(b=>{
        if(!b.dataset.keywords)return;
        b.addEventListener('click',()=>{
            const kws=b.dataset.keywords.split('||');
            if(!el.kwInput)return;
            const cur=el.kwInput.value.trim();
            el.kwInput.value=cur?cur+'\n'+kws.join('\n'):kws.join('\n');
            updateCounts();toast('Added '+kws.length+' keywords');
        });
    });
    el.opAll?.addEventListener('click',()=>toggleAll(el.opGrid,true));
    el.opNone?.addEventListener('click',()=>toggleAll(el.opGrid,false));
    el.ftAll?.addEventListener('click',()=>toggleAll(el.ftGrid,true));
    el.ftNone?.addEventListener('click',()=>toggleAll(el.ftGrid,false));
    el.vpAll?.addEventListener('click',()=>{toggleAll(el.vpGrid,true);updateVpCount()});
    el.vpNone?.addEventListener('click',()=>{toggleAll(el.vpGrid,false);updateVpCount()});
    el.genAll?.addEventListener('change',syncGenAll);
    el.genSearch?.addEventListener('input',applyGenFilter);
    el.genSort?.addEventListener('click',sortGen);
    el.genShuffle?.addEventListener('click',shuffleGen);
    el.copyAll?.addEventListener('click',()=>{if(!filteredDorks.length)return;clip(filteredDorks.join('\n'));toast('Copied '+filteredDorks.length+' dorks')});
    el.copySel?.addEventListener('click',()=>{
        const s=[...selectedRows].sort((a,b)=>a-b).map(i=>filteredDorks[i]).filter(Boolean);
        if(!s.length)return;clip(s.join('\n'));toast('Copied '+s.length+' dorks');
    });
    el.expTxt?.addEventListener('click',()=>exportDorks('txt'));
    el.expCsv?.addEventListener('click',()=>exportDorks('csv'));
    el.expJson?.addEventListener('click',()=>exportDorks('json'));
    el.sendHunt?.addEventListener('click',()=>{
        if(!filteredDorks.length)return;
        if(el.huntDorks)el.huntDorks.value=filteredDorks.join('\n');
        updateHuntDorkCount();switchMode('hunter');toast('Sent '+filteredDorks.length+' dorks to Hunter');
    });
    el.sendScan?.addEventListener('click',()=>{
        if(!filteredDorks.length)return;
        toast('Use Hunter first to extract URLs, then scan them','warn');switchMode('hunter');
    });
    document.addEventListener('keydown',e=>{
        if((e.ctrlKey||e.metaKey)&&e.key==='Enter'){
            e.preventDefault();
            if(currentMode==='generator')generate();
            else if(currentMode==='hunter')huntSearch();
            else if(currentMode==='scanner')startScan();
        }
    });
}
function syncGenAll(){
    const on=el.genAll?.checked||false;
    if(el.maxResults){el.maxResults.disabled=on;if(on){el.maxResults.dataset.prev=el.maxResults.value;el.maxResults.value='0'}else{el.maxResults.value=el.maxResults.dataset.prev||'100'}}
}
function updateCounts(){
    const kws=getKws(),ops=getOps(),fts=getFts();
    if(el.kwCount)el.kwCount.textContent=kws.length;
    if(el.opCount)el.opCount.textContent=ops.length;
    if(el.ftCount)el.ftCount.textContent=fts.length;
    const k=kws.length,nonFt=ops.filter(o=>!['filetype','ext','mime'].includes(o)),o=nonFt.length,f=fts.length;
    let p=0;
    if(o>0&&f>0){p+=o*k*f+k*f;if(o>=2){const c=o*(o-1)/2;p+=c*k+c*k*f}}
    else if(o>0){p+=o*k;if(o>=2)p+=o*(o-1)/2*k}
    else if(f>0)p+=k*f;
    else p+=k;
    const vps=getVps();
    if(vps.length>0&&k>0){
        p+=vps.length*k;
        p+=vps.length*nonFt.filter(x=>x!=='inurl').length*k;
    }
    if(el.statPossibleVal)el.statPossibleVal.textContent=p.toLocaleString();
}
function getKws(){return el.kwInput?el.kwInput.value.split('\n').map(l=>l.trim()).filter(l=>l):[]}
function getOps(){return el.opGrid?[...el.opGrid.querySelectorAll('.chip--on')].map(c=>c.dataset.operator):[]}
function getFts(){return el.ftGrid?[...el.ftGrid.querySelectorAll('.chip--on')].map(c=>c.dataset.filetype):[]}

async function generate(){
    const kws=getKws();if(!kws.length){toast('Enter keywords','warn');el.kwInput?.focus();return}
    const genAllOn=el.genAll?.checked||false;
    let max=parseInt(el.maxResults?.value,10);if(isNaN(max)||max<0)max=100;if(genAllOn)max=0;
    const body={engine:currentEngine,keywords:kws,operators:getOps(),filetypes:getFts(),
        site:el.siteInput?.value.trim()||'',use_quotes:el.useQuotes?.checked||false,
        exclusions:(el.exclInput?.value||'').split('\n').map(l=>l.trim()).filter(l=>l),
        max_results:max,vuln_params:getVps()};
    showLoad('Generating...',max===0?'Generating ALL combinations...':'Processing');
    el.genBtn&&(el.genBtn.disabled=true);
    try{
        const r=await fetch('/api/generate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
        if(!r.ok)throw new Error('HTTP '+r.status);
        const d=await r.json();if(d.error){toast(d.error,'err');return}
        allDorks=d.dorks||[];filteredDorks=[...allDorks];selectedRows.clear();
        if(el.statGeneratedVal)el.statGeneratedVal.textContent=d.total_generated.toLocaleString();
        if(el.statPossibleVal)el.statPossibleVal.textContent=d.total_possible.toLocaleString();
        renderGen();updateGenBtns();
        if(allDorks.length)toast(`Generated ${allDorks.length.toLocaleString()} dorks for ${d.engine_name}`);
        else toast('No dorks generated','warn');
    }catch(e){toast('Error: '+e.message,'err')}
    finally{hideLoad();el.genBtn&&(el.genBtn.disabled=false)}
}
function renderGen(){if(el.genSearch)el.genSearch.value='';renderGenFiltered()}
function renderGenFiltered(){
    if(!filteredDorks.length){showEl(el.genEmpty);hideEl(el.genList);if(el.genResCount)el.genResCount.textContent='0 dorks';return}
    hideEl(el.genEmpty);showEl(el.genList);
    const frag=document.createDocumentFragment();
    const limit=Math.min(filteredDorks.length,RENDER_LIMIT);
    for(let i=0;i<limit;i++){frag.appendChild(mkDorkRow(filteredDorks[i],i+1))}
    el.genList.innerHTML='';el.genList.appendChild(frag);
    let countText=filteredDorks.length.toLocaleString()+' dorks';
    if(filteredDorks.length>RENDER_LIMIT)countText+=` (showing ${RENDER_LIMIT})`;
    if(el.genResCount)el.genResCount.textContent=countText;
}
function mkDorkRow(dork,n){
    const row=document.createElement('div');row.className='dork-row';row.dataset.index=n-1;
    const num=document.createElement('div');num.className='dork-row__num';num.textContent=n;
    const txt=document.createElement('div');txt.className='dork-row__text';txt.innerHTML=hlDork(dork);
    const cp=document.createElement('button');cp.type='button';cp.className='dork-row__copy';
    cp.textContent='Copy';cp.title='Copy';
    cp.addEventListener('click',e=>{e.stopPropagation();clip(dork);toast('Copied')});
    row.addEventListener('click',()=>{
        const i=parseInt(row.dataset.index,10);
        if(selectedRows.has(i)){selectedRows.delete(i);row.classList.remove('dork-row--sel')}
        else{selectedRows.add(i);row.classList.add('dork-row--sel')}
        updateGenBtns();
    });
    row.append(num,txt,cp);return row;
}
function hlDork(d){
    let h=esc(d);
    h=h.replace(/\b([\w.]+):(&quot;[^&]*&quot;)/gi,(m,o,v)=>['filetype','ext','mime'].includes(o.toLowerCase())?`<span class="op">${o}:</span><span class="ft">${v}</span>`:`<span class="op">${o}:</span><span class="qt">${v}</span>`);
    h=h.replace(/\b([\w.]+):(\S+)/gi,(m,o,v)=>{if(m.includes('<span'))return m;return['filetype','ext','mime'].includes(o.toLowerCase())?`<span class="op">${o}:</span><span class="ft">${v}</span>`:`<span class="op">${o}:</span><span class="kw">${v}</span>`});
    h=h.replace(/\b(in:\w+)\s+(\S+)/gi,(m,o,v)=>m.includes('<span')?m:`<span class="op">${o}</span> <span class="kw">${v}</span>`);
    h=h.replace(/(^|\s)(-\S+)/g,'$1<span class="neg">$2</span>');
    return h.trim();
}
function applyGenFilter(){
    const t=el.genSearch?.value.trim().toLowerCase()||'';
    filteredDorks=t?allDorks.filter(d=>d.toLowerCase().includes(t)):[...allDorks];
    selectedRows.clear();renderGenFiltered();updateGenBtns();
}
function sortGen(){filteredDorks.sort((a,b)=>sortAsc?a.localeCompare(b):b.localeCompare(a));sortAsc=!sortAsc;if(el.genSort)el.genSort.textContent=sortAsc?'A-Z':'Z-A';selectedRows.clear();renderGenFiltered();updateGenBtns()}
function shuffleGen(){for(let i=filteredDorks.length-1;i>0;i--){const j=Math.floor(Math.random()*(i+1));[filteredDorks[i],filteredDorks[j]]=[filteredDorks[j],filteredDorks[i]]}selectedRows.clear();renderGenFiltered();updateGenBtns()}
function updateGenBtns(){
    const has=filteredDorks.length>0,sel=selectedRows.size>0;
    [el.copyAll,el.expTxt,el.expCsv,el.expJson,el.sendHunt,el.sendScan].forEach(b=>b&&(b.disabled=!has));
    el.copySel&&(el.copySel.disabled=!sel);
}
async function exportDorks(fmt){
    if(!filteredDorks.length)return;
    const eng=engineConfig?.engines?.[currentEngine];
    try{
        const r=await fetch('/api/export',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({dorks:filteredDorks,format:fmt,engine_name:eng?.name||currentEngine})});
        if(!r.ok)throw new Error('HTTP '+r.status);
        dl(await r.blob(),`dorkmaster_export.${fmt}`);toast(`Exported as ${fmt.toUpperCase()}`);
    }catch(e){toast('Export failed','err')}
}

/* -- Hunter -- */
function bindHunt(){
    el.huntBtn?.addEventListener('click',huntSearch);
    el.huntDorks?.addEventListener('input',updateHuntDorkCount);
    el.huntFileUpload?.addEventListener('change',e=>fileUpload(e,el.huntDorks,updateHuntDorkCount));
    el.huntClearDorks?.addEventListener('click',()=>{if(el.huntDorks)el.huntDorks.value='';updateHuntDorkCount()});
    el.huntEngines?.querySelectorAll('.chip').forEach(c=>c.addEventListener('click',()=>c.classList.toggle('chip--on')));
    el.huntSearch?.addEventListener('input',applyHuntFilter);
    el.huntCopyAll?.addEventListener('click',()=>{if(!huntFiltered.length)return;clip(huntFiltered.join('\n'));toast('Copied '+huntFiltered.length+' URLs')});
    el.huntExpTxt?.addEventListener('click',()=>exportHunt('txt'));
    el.huntExpCsv?.addEventListener('click',()=>exportHunt('csv'));
    el.huntExpJson?.addEventListener('click',()=>exportHunt('json'));
    el.sendUrlsToScan?.addEventListener('click',()=>{
        if(!huntFiltered.length)return;
        if(el.scanUrls)el.scanUrls.value=huntFiltered.join('\n');
        updateScanUrlCount();switchMode('scanner');toast('Sent '+huntFiltered.length+' URLs to Scanner');
    });
    el.huntModeCardFree?.addEventListener('click',()=>setHuntMode('free'));
    el.huntModeCardApi?.addEventListener('click',()=>setHuntMode('api'));
    // Debug log toggle
    el.toggleLog?.addEventListener('click',()=>{
        showDebugLog=!showDebugLog;
        if(showDebugLog){showEl(el.debugLog);el.toggleLog.classList.add('btn--teal');el.toggleLog.classList.remove('btn--ghost')}
        else{hideEl(el.debugLog);el.toggleLog.classList.remove('btn--teal');el.toggleLog.classList.add('btn--ghost')}
    });
    el.clearLog?.addEventListener('click',()=>{if(el.debugLogBody)el.debugLogBody.innerHTML=''});
}
function setHuntMode(mode){
    huntSearchMode=mode;
    el.huntModeCardFree?.classList.toggle('mode-card--active',mode==='free');
    el.huntModeCardApi?.classList.toggle('mode-card--active',mode==='api');
    if(el.huntFreeEnginesCard){el.huntFreeEnginesCard.style.display=mode==='free'?'':'none'}
    if(el.huntBtn){
        if(mode==='api'){
            el.huntBtn.innerHTML='<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg> Start PREMIUM Hunt';
            el.huntBtn.className='btn btn--premium btn--lg btn--block';
        }else{
            el.huntBtn.innerHTML='<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg> Start Hunting';
            el.huntBtn.className='btn btn--primary btn--lg btn--block';
        }
    }
    updateHuntQuotaBar();
}
function updateHuntQuotaBar(){
    if(huntSearchMode==='api'&&quotaData){
        showEl(el.quotaBarHunter);
        const pct=quotaData.total_capacity>0?Math.round(quotaData.total_used/quotaData.total_capacity*100):0;
        if(el.quotaFillHunter)el.quotaFillHunter.style.width=pct+'%';
        if(el.quotaTextHunter)el.quotaTextHunter.textContent=`${quotaData.total_used.toLocaleString()} / ${quotaData.total_capacity.toLocaleString()} used`;
        if(el.quotaRemHunter)el.quotaRemHunter.textContent=`${quotaData.total_remaining.toLocaleString()} remaining`;
    }else{
        hideEl(el.quotaBarHunter);
    }
}
function updateHuntDorkCount(){if(el.huntDorks&&el.huntDorkCount)el.huntDorkCount.textContent=el.huntDorks.value.split('\n').filter(l=>l.trim()).length}

function addLogLine(msg){
    if(!el.debugLogBody)return;
    const div=document.createElement('div');
    div.className='debug-log__line';
    if(msg.startsWith('[+]'))div.className+=' debug-log__line--found';
    else if(msg.startsWith('[!]'))div.className+=' debug-log__line--error';
    else div.className+=' debug-log__line--info';
    div.textContent=msg;
    el.debugLogBody.appendChild(div);
    el.debugLogBody.scrollTop=el.debugLogBody.scrollHeight;
}

function updateEngineStatus(status){
    if(!el.engineStatusBar)return;
    let item=el.engineStatusBar.querySelector(`[data-engine="${status.engine}"]`);
    if(!item){
        item=document.createElement('div');
        item.className='engine-status';
        item.dataset.engine=status.engine;
        item.innerHTML=`<span class="engine-status__dot engine-status__dot--pending"></span><span class="engine-status__name">${esc(status.name)}</span><span class="engine-status__info"></span>`;
        el.engineStatusBar.appendChild(item);
    }
    const dot=item.querySelector('.engine-status__dot');
    if(dot){
        dot.className='engine-status__dot engine-status__dot--'+status.status;
    }
    const info=item.querySelector('.engine-status__info');
    if(info){
        info.textContent=`${status.queries_done}/${status.queries_total} | ${status.urls_found} URLs`;
        if(status.errors>0)info.textContent+=` | ${status.errors} err`;
    }
}

async function huntSearch(){
    if(isHunting)return;
    const dorks=el.huntDorks?.value.split('\n').map(l=>l.trim()).filter(l=>l)||[];
    if(!dorks.length){toast('Enter dork queries','warn');el.huntDorks?.focus();return}
    const useProxy=el.huntUseProxy?.checked||false;

    let engs=[];
    if(huntSearchMode==='free'){
        engs=[...el.huntEngines?.querySelectorAll('.chip--on')||[]].map(c=>c.dataset.engine).filter(e=>['duckduckgo','bing','yahoo','google','ask'].includes(e));
        if(!engs.length){toast('Select at least one engine','warn');return}
    }

    if(huntSearchMode==='api'){
        if(!quotaData||quotaData.total_keys===0){toast('No API keys configured! Go to Settings.','err');return}
        if(quotaData.total_remaining===0){toast('All API keys exhausted.','err');return}
    }

    const pages=parseInt(el.huntPages?.value,10)||1;
    const conc=parseInt(el.huntConc?.value,10)||3;
    const delayMin=parseFloat(el.huntDelayMin?.value)||1.0;
    const delayMax=parseFloat(el.huntDelayMax?.value)||3.0;

    isHunting=true;huntUrls=[];huntFiltered=[];
    showEl(el.huntProgress);hideEl(el.huntEmpty);showEl(el.huntList);
    if(huntSearchMode==='free')showEl(el.engineStatusBar);else hideEl(el.engineStatusBar);
    if(el.engineStatusBar)el.engineStatusBar.innerHTML='';
    if(el.huntList)el.huntList.innerHTML='';
    if(el.debugLogBody)el.debugLogBody.innerHTML='';
    setProgress(el.huntProgressFill,5);

    const totalQueries=dorks.length*engs.length*pages;
    const modeLabel=huntSearchMode==='api'?'Serper API (PREMIUM)':engs.join(', ')+' (FREE)';
    if(el.huntProgressText)el.huntProgressText.textContent=`Progress: 0% (0/${totalQueries} queries) via ${modeLabel}`;
    if(el.huntProgressNum)el.huntProgressNum.textContent='0 URLs';
    el.huntBtn&&(el.huntBtn.disabled=true);
    updateHuntBtns();
    let cnt=0;
    try{
        const body={dorks,search_mode:huntSearchMode,engines:engs,pages_per_dork:pages,max_concurrency:conc,use_proxy:useProxy,delay_min:delayMin,delay_max:delayMax};
        const r=await fetch('/api/hunter/search/stream',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
        if(!r.ok){
            const errData=await r.json().catch(()=>({}));
            throw new Error(errData.error||'HTTP '+r.status);
        }
        const reader=r.body.getReader(),dec=new TextDecoder();let buf='',evtType='';
        while(true){
            const{done,value}=await reader.read();if(done)break;
            buf+=dec.decode(value,{stream:true});const lines=buf.split('\n');buf=lines.pop()||'';
            for(const ln of lines){
                if(ln.startsWith('event: '))evtType=ln.substring(7).trim();
                else if(ln.startsWith('data: ')){
                    try{
                        const d=JSON.parse(ln.substring(6));
                        if(evtType==='url'){
                            cnt++;huntUrls.push(d.url);huntFiltered.push(d.url);
                            if(cnt<=RENDER_LIMIT)appendUrl(d.url,cnt);
                            if(el.huntUrlCount)el.huntUrlCount.textContent=cnt+' URLs';
                            if(el.huntProgressNum)el.huntProgressNum.textContent=cnt+' URLs';
                        }
                        else if(evtType==='progress'){
                            const pct=d.percent||0;
                            setProgress(el.huntProgressFill,Math.max(5,pct));
                            if(el.huntProgressText)el.huntProgressText.textContent=`Progress: ${Math.round(pct)}% (${d.completed||0}/${d.total||totalQueries} queries)`;
                        }
                        else if(evtType==='engine_status'){
                            updateEngineStatus(d);
                        }
                        else if(evtType==='log'){
                            addLogLine(d.message||'');
                        }
                        else if(evtType==='done'){
                            setProgress(el.huntProgressFill,100);
                            if(el.huntProgressText)el.huntProgressText.textContent='Done!';
                            if(el.huntProgressNum)el.huntProgressNum.textContent=(d.total_urls||cnt)+' URLs';
                            if(d.quota){quotaData=d.quota;updateHuntQuotaBar();
                                const qUsed=d.queries_used||0;
                                if(qUsed>0)toast(`PREMIUM: Used ${qUsed} API queries. ${d.quota.total_remaining.toLocaleString()} remaining.`);
                            }
                            // Final engine states
                            if(d.engine_states){
                                d.engine_states.forEach(s=>updateEngineStatus(s));
                            }
                        }
                        else if(evtType==='error')toast('Error: '+(d.error||'Unknown'),'err');
                    }catch(_){}evtType='';
                }
            }
        }
        if(huntUrls.length>RENDER_LIMIT)renderHuntList();
        updateHuntBtns();
        const modeText=huntSearchMode==='api'?'(PREMIUM)':'(FREE)';
        toast(huntUrls.length?`Extracted ${huntUrls.length} URLs ${modeText}`:`No URLs found ${modeText}`,huntUrls.length?undefined:'warn');
        if(!huntUrls.length){showEl(el.huntEmpty);hideEl(el.huntList)}
    }catch(e){toast('Hunt failed: '+e.message,'err')}
    finally{
        isHunting=false;el.huntBtn&&(el.huntBtn.disabled=false);
        setHuntMode(huntSearchMode);
        setTimeout(()=>hideEl(el.huntProgress),5000);
    }
}
function appendUrl(url,n){if(!el.huntList)return;el.huntList.appendChild(mkUrlRow(url,n));if(el.huntBody)el.huntBody.scrollTop=el.huntBody.scrollHeight}
function mkUrlRow(url,n){
    const row=document.createElement('div');row.className='url-row';
    const num=document.createElement('div');num.className='url-row__num';num.textContent=n;
    const txt=document.createElement('div');txt.className='url-row__text';
    const a=document.createElement('a');a.href=url;a.target='_blank';a.rel='noopener';a.textContent=url;txt.appendChild(a);
    const cp=document.createElement('button');cp.type='button';cp.className='url-row__copy';cp.textContent='Copy';cp.title='Copy';
    cp.addEventListener('click',e=>{e.stopPropagation();clip(url);toast('Copied')});
    row.append(num,txt,cp);return row;
}
function applyHuntFilter(){
    const t=el.huntSearch?.value.trim().toLowerCase()||'';
    huntFiltered=t?huntUrls.filter(u=>u.toLowerCase().includes(t)):[...huntUrls];
    renderHuntList();updateHuntBtns();
}
function renderHuntList(){
    if(!huntFiltered.length){showEl(el.huntEmpty);hideEl(el.huntList);if(el.huntUrlCount)el.huntUrlCount.textContent='0 URLs';return}
    hideEl(el.huntEmpty);showEl(el.huntList);
    const frag=document.createDocumentFragment();
    const limit=Math.min(huntFiltered.length,RENDER_LIMIT);
    for(let i=0;i<limit;i++){frag.appendChild(mkUrlRow(huntFiltered[i],i+1))}
    el.huntList.innerHTML='';el.huntList.appendChild(frag);
    let countText=huntFiltered.length.toLocaleString()+' URLs';
    if(huntFiltered.length>RENDER_LIMIT)countText+=` (showing ${RENDER_LIMIT})`;
    if(el.huntUrlCount)el.huntUrlCount.textContent=countText;
}
function updateHuntBtns(){
    const has=huntFiltered.length>0;
    [el.huntCopyAll,el.huntExpTxt,el.huntExpCsv,el.huntExpJson,el.sendUrlsToScan].forEach(b=>b&&(b.disabled=!has));
}
async function exportHunt(fmt){
    if(!huntFiltered.length)return;
    try{
        const r=await fetch('/api/hunter/export',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({urls:huntFiltered,format:fmt})});
        if(!r.ok)throw new Error('HTTP '+r.status);
        dl(await r.blob(),`dorkmaster_urls.${fmt}`);toast(`Exported as ${fmt.toUpperCase()}`);
    }catch(e){toast('Export failed','err')}
}

/* -- Scanner -- */
function bindScan(){
    el.scanBtn?.addEventListener('click',startScan);
    el.scanUrls?.addEventListener('input',updateScanUrlCount);
    el.scanFileUpload?.addEventListener('change',e=>fileUpload(e,el.scanUrls,updateScanUrlCount));
    el.scanClearUrls?.addEventListener('click',()=>{if(el.scanUrls)el.scanUrls.value='';updateScanUrlCount()});
    el.scanSearch?.addEventListener('input',applyScanFilter);
    el.scanCopyFindings?.addEventListener('click',copyScanFindings);
    el.scanExpTxt?.addEventListener('click',()=>exportScan('txt'));
    el.scanExpCsv?.addEventListener('click',()=>exportScan('csv'));
    el.scanExpJson?.addEventListener('click',()=>exportScan('json'));
}
function updateScanUrlCount(){if(el.scanUrls&&el.scanUrlCount)el.scanUrlCount.textContent=el.scanUrls.value.split('\n').filter(l=>l.trim()).length}
async function startScan(){
    if(isScanning)return;
    const urls=el.scanUrls?.value.split('\n').map(l=>l.trim()).filter(l=>l)||[];
    if(!urls.length){toast('Enter URLs','warn');el.scanUrls?.focus();return}
    const sqli=el.scanSqli?.checked??true,xss=el.scanXss?.checked??true;
    if(!sqli&&!xss){toast('Enable at least one detection','warn');return}
    const conc=parseInt(el.scanConc?.value,10)||20,timeout=parseInt(el.scanTimeout?.value,10)||10,rate=parseInt(el.scanRate?.value,10)||50;
    const useProxy=el.scanUseProxy?.checked||false;
    isScanning=true;scanReport=null;scanFiltered=[];
    showEl(el.scanProgress);hideEl(el.scanEmpty);hideEl(el.scanSummary);hideEl(el.scanList);
    setProgress(el.scanProgressFill,2);
    if(el.scanProgressText)el.scanProgressText.textContent='Scanning '+urls.length+' URLs'+(useProxy?' (via proxy)':'')+'...';
    if(el.scanProgressNum)el.scanProgressNum.textContent='0%';
    el.scanBtn&&(el.scanBtn.disabled=true);el.scanBtn&&(el.scanBtn.textContent='Scanning...');
    updateScanBtns();
    try{
        const r=await fetch('/api/scanner/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({urls,detect_sqli:sqli,detect_xss:xss,max_concurrency:conc,timeout:timeout,rate_limit:rate,use_proxy:useProxy})});
        if(!r.ok)throw new Error('HTTP '+r.status);
        const reader=r.body.getReader(),dec=new TextDecoder();let buf='',evtType='';
        while(true){
            const{done,value}=await reader.read();if(done)break;
            buf+=dec.decode(value,{stream:true});const lines=buf.split('\n');buf=lines.pop()||'';
            for(const ln of lines){
                if(ln.startsWith('event: '))evtType=ln.substring(7).trim();
                else if(ln.startsWith('data: ')){
                    try{
                        const d=JSON.parse(ln.substring(6));
                        if(evtType==='progress'){
                            setProgress(el.scanProgressFill,d.percent||0);
                            if(el.scanProgressNum)el.scanProgressNum.textContent=Math.round(d.percent||0)+'%';
                            if(el.scanProgressText)el.scanProgressText.textContent=`Scanning ${d.current}/${d.total}...`;
                        }else if(evtType==='done'){
                            scanReport=d;
                            setProgress(el.scanProgressFill,100);
                            if(el.scanProgressText)el.scanProgressText.textContent='Scan complete!';
                            if(el.scanProgressNum)el.scanProgressNum.textContent='100%';
                            renderScanResults();
                        }else if(evtType==='error'){toast('Scan error: '+(d.error||'Unknown'),'err')}
                    }catch(_){}evtType='';
                }
            }
        }
        if(scanReport){
            const s=scanReport.summary||{};
            toast(`Scan done: ${s.total_findings||0} findings in ${s.total_urls||0} URLs`);
        }else{toast('Scan returned no results','warn')}
    }catch(e){toast('Scan failed: '+e.message,'err')}
    finally{
        isScanning=false;el.scanBtn&&(el.scanBtn.disabled=false);
        el.scanBtn&&(el.scanBtn.textContent='Start Scan');
        setTimeout(()=>hideEl(el.scanProgress),3000);
    }
}
function renderScanResults(){
    if(!scanReport)return;
    const s=scanReport.summary||{},results=scanReport.results||[];
    scanFiltered=[...results];
    showEl(el.scanSummary);
    if(el.sumUrls)el.sumUrls.textContent=s.total_urls||0;
    if(el.sumFindings)el.sumFindings.textContent=s.total_findings||0;
    if(el.sumSqli)el.sumSqli.textContent=(s.vuln_counts||{}).SQLi||0;
    if(el.sumXss)el.sumXss.textContent=(s.vuln_counts||{}).XSS||0;
    if(el.scanResCount)el.scanResCount.textContent=(s.total_findings||0)+' findings';
    renderScanList();updateScanBtns();
}
function renderScanList(){
    if(!scanFiltered.length){showEl(el.scanEmpty);hideEl(el.scanList);return}
    hideEl(el.scanEmpty);showEl(el.scanList);
    const frag=document.createDocumentFragment();
    const limit=Math.min(scanFiltered.length,RENDER_LIMIT);
    for(let i=0;i<limit;i++){frag.appendChild(mkScanRow(scanFiltered[i]))}
    el.scanList.innerHTML='';el.scanList.appendChild(frag);
}
function mkScanRow(r){
    const row=document.createElement('div');row.className='scan-row';
    const urlDiv=document.createElement('div');urlDiv.className='scan-row__url';
    const statusCls={'vulnerable':'vuln','clean':'clean','error':'error','skipped':'skip'};
    const badge=document.createElement('span');badge.className='scan-row__status scan-row__status--'+(statusCls[r.status]||'skip');
    badge.textContent=r.status;
    urlDiv.textContent=r.url;urlDiv.prepend(badge);
    row.appendChild(urlDiv);
    if(r.findings&&r.findings.length){
        const fd=document.createElement('div');fd.className='scan-row__findings';
        r.findings.forEach(f=>{
            const finding=document.createElement('div');finding.className='scan-finding';
            const head=document.createElement('div');head.className='scan-finding__head';
            const type=document.createElement('span');type.className='scan-finding__type scan-finding__type--'+(f.vuln_type==='SQLi'?'sqli':'xss');type.textContent=f.vuln_type;
            const conf=document.createElement('span');conf.className='scan-finding__conf scan-finding__conf--'+f.confidence;conf.textContent=f.confidence;
            const param=document.createElement('span');param.className='scan-finding__param';param.textContent='param='+f.parameter;
            head.append(type,conf,param);
            const ev=document.createElement('div');ev.className='scan-finding__evidence';ev.textContent=f.evidence;
            finding.append(head,ev);fd.appendChild(finding);
        });
        row.appendChild(fd);
    }
    if(r.error){const err=document.createElement('div');err.style.cssText='font-size:.7rem;color:var(--red);margin-top:.2rem';err.textContent='Error: '+r.error;row.appendChild(err)}
    return row;
}
function applyScanFilter(){
    if(!scanReport)return;
    const t=el.scanSearch?.value.trim().toLowerCase()||'';
    scanFiltered=t?(scanReport.results||[]).filter(r=>r.url.toLowerCase().includes(t)||(r.findings||[]).some(f=>f.evidence.toLowerCase().includes(t)||f.parameter.toLowerCase().includes(t))):[...(scanReport.results||[])];
    renderScanList();
}
function updateScanBtns(){
    const has=scanReport&&(scanReport.results||[]).length>0;
    [el.scanCopyFindings,el.scanExpTxt,el.scanExpCsv,el.scanExpJson].forEach(b=>b&&(b.disabled=!has));
}
function copyScanFindings(){
    if(!scanReport)return;
    const lines=[];
    (scanReport.results||[]).forEach(r=>{
        if(r.findings&&r.findings.length){
            lines.push(r.url);
            r.findings.forEach(f=>lines.push(`  [${f.confidence}] ${f.vuln_type} | param=${f.parameter} | ${f.evidence}`));
        }
    });
    if(!lines.length){toast('No findings to copy','warn');return}
    clip(lines.join('\n'));toast('Copied '+lines.length+' lines');
}
async function exportScan(fmt){
    if(!scanReport)return;
    try{
        const r=await fetch('/api/scanner/export',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({...scanReport,format:fmt})});
        if(!r.ok)throw new Error('HTTP '+r.status);
        dl(await r.blob(),`scan_report.${fmt}`);toast(`Exported as ${fmt.toUpperCase()}`);
    }catch(e){toast('Export failed','err')}
}

/* -- Settings -- */
function bindSettings(){
    el.saveKeysBtn?.addEventListener('click',async()=>{
        const keys=(el.setSerperKeys?.value||'').split('\n').map(k=>k.trim()).filter(k=>k);
        try{
            const r=await fetch('/api/settings/api-keys',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({serper_api_keys:keys})});
            const d=await r.json();
            toast(d.message||'Saved');
            if(d.quota)quotaData=d.quota;
            loadStatus();
        }catch(e){toast('Failed','err')}
    });
    el.saveProxiesBtn?.addEventListener('click',async()=>{
        const proxies=(el.setProxies?.value||'').split('\n').map(p=>p.trim()).filter(p=>p);
        const enabled=el.setProxyOn?.checked||false;
        try{const r=await fetch('/api/settings/proxies',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({proxies,enabled})});const d=await r.json();toast(d.message||'Saved');loadStatus()}catch(e){toast('Failed','err')}
    });
    el.proxyFileUpload?.addEventListener('change',e=>fileUpload(e,el.setProxies));
    el.testProxiesBtn?.addEventListener('click',async()=>{
        const proxies=(el.setProxies?.value||'').split('\n').map(p=>p.trim()).filter(p=>p);
        if(!proxies.length){toast('No proxies','warn');return}
        showEl(el.proxyTestBox);if(el.proxyTestSummary)el.proxyTestSummary.textContent='Testing '+proxies.length+'...';
        if(el.proxyTestList)el.proxyTestList.innerHTML='';hideEl(el.saveWorkingBtn);
        el.testProxiesBtn&&(el.testProxiesBtn.disabled=true);
        try{
            const r=await fetch('/api/settings/proxies/test',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({proxies,timeout:10})});
            const d=await r.json();
            if(el.proxyTestSummary)el.proxyTestSummary.textContent=`${d.total_working}/${d.total_tested} working`;
            let html='';
            (d.working||[]).forEach(p=>html+=`<div class="proxy-test-item proxy-test-item--ok"><span>${esc(p)}</span><span>OK</span></div>`);
            (d.failed||[]).forEach(p=>html+=`<div class="proxy-test-item proxy-test-item--fail"><span>${esc(p)}</span><span>FAIL</span></div>`);
            if(el.proxyTestList)el.proxyTestList.innerHTML=html;
            if(d.total_working>0){showEl(el.saveWorkingBtn);el.saveWorkingBtn.onclick=async()=>{
                try{await fetch('/api/settings/proxies/save-working',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({working:d.working})});
                if(el.setProxies)el.setProxies.value=d.working.join('\n');if(el.setProxyOn)el.setProxyOn.checked=true;toast('Saved working proxies');loadStatus()}catch(err){toast('Failed','err')}
            }}
            toast(`${d.total_working}/${d.total_tested} working`);
        }catch(e){toast('Test failed','err')}
        finally{el.testProxiesBtn&&(el.testProxiesBtn.disabled=false)}
    });
    el.resetQuotaBtn?.addEventListener('click',async()=>{
        if(!confirm('Reset all quota counters to 0?'))return;
        try{
            const r=await fetch('/api/settings/quota/reset',{method:'POST',headers:{'Content-Type':'application/json'}});
            const d=await r.json();
            toast(d.message||'Reset');
            if(d.quota)quotaData=d.quota;
            renderQuota();
        }catch(e){toast('Failed','err')}
    });
}
async function loadStatus(){
    try{
        const r=await fetch('/api/settings');if(!r.ok)return;const d=await r.json();
        const kc=d.serper_api_keys_count||0;
        if(el.stSerper){el.stSerper.textContent=kc>0?kc+' key(s)':'None';el.stSerper.className='status-val'+(kc>0?'':' status-val--off')}
        if(el.stProxy){el.stProxy.textContent=d.proxy_enabled?'Enabled':'Disabled';el.stProxy.className='status-val'+(d.proxy_enabled?'':' status-val--off')}
        if(el.stProxyCount){el.stProxyCount.textContent=(d.proxy_count||0)+' proxies';el.stProxyCount.className='status-val'+((d.proxy_count||0)>0?'':' status-val--off')}
        if(el.setProxyOn)el.setProxyOn.checked=d.proxy_enabled;
        if(d.proxies&&el.setProxies&&!el.setProxies.value)el.setProxies.value=d.proxies.join('\n');
        if(d.quota){quotaData=d.quota;renderQuota()}
    }catch(_){}
}
function renderQuota(){
    if(!quotaData)return;
    if(el.quotaBadge)el.quotaBadge.textContent=quotaData.total_remaining.toLocaleString()+' left';
    if(el.quotaCapacity)el.quotaCapacity.textContent=quotaData.total_capacity.toLocaleString();
    if(el.quotaUsed)el.quotaUsed.textContent=quotaData.total_used.toLocaleString();
    if(el.quotaRemaining)el.quotaRemaining.textContent=quotaData.total_remaining.toLocaleString();
    const pct=quotaData.total_capacity>0?Math.round(quotaData.total_used/quotaData.total_capacity*100):0;
    if(el.quotaFillSettings)el.quotaFillSettings.style.width=pct+'%';
    if(el.quotaKeyList){
        if(!quotaData.keys||!quotaData.keys.length){
            el.quotaKeyList.innerHTML='<p class="hint">No API keys configured.</p>';
        }else{
            let html='';
            quotaData.keys.forEach(k=>{
                const color=k.percent_used<50?'var(--green)':k.percent_used<80?'var(--yellow)':'var(--red)';
                html+=`<div class="quota-key-row">
                    <span class="quota-key-row__label">Key ${k.index}: ${esc(k.masked)}</span>
                    <div class="quota-key-row__bar"><div class="quota-key-row__fill" style="width:${k.percent_used}%;background:${color}"></div></div>
                    <span class="quota-key-row__info">${k.remaining.toLocaleString()} / ${k.capacity.toLocaleString()}</span>
                </div>`;
            });
            el.quotaKeyList.innerHTML=html;
        }
    }
    updateHuntQuotaBar();
}

/* -- Utilities -- */
function showEl(e){if(e)e.style.display=''}
function hideEl(e){if(e)e.style.display='none'}
function showLoad(t,s){showEl(el.overlay);if(el.overlayTitle)el.overlayTitle.textContent=t||'Processing...';if(el.overlaySub)el.overlaySub.textContent=s||'Please wait'}
function hideLoad(){hideEl(el.overlay)}
function toggleAll(g,on){if(!g)return;g.querySelectorAll('.chip').forEach(c=>{if(on)c.classList.add('chip--on');else c.classList.remove('chip--on')});updateCounts()}
function setProgress(fillEl,pct){
    if(!fillEl)return;
    const p=Math.min(100,Math.max(0,pct));
    fillEl.innerHTML=`<div style="height:100%;width:${p}%;background:linear-gradient(90deg,var(--teal),var(--blue));border-radius:2px;transition:width .3s ease"></div>`;
}
function fileUpload(e,target,cb){
    const f=e.target.files?.[0];if(!f||!target)return;
    const r=new FileReader();r.onload=ev=>{
        const lines=ev.target.result.split('\n').filter(l=>l.trim());
        const cur=target.value.trim();
        target.value=cur?cur+'\n'+lines.join('\n'):lines.join('\n');
        toast('Loaded '+lines.length+' lines');cb&&cb();
    };r.readAsText(f);e.target.value='';
}
async function clip(t){try{await navigator.clipboard.writeText(t)}catch{const a=document.createElement('textarea');a.value=t;a.style.cssText='position:fixed;left:-9999px';document.body.appendChild(a);a.select();try{document.execCommand('copy')}catch{}document.body.removeChild(a)}}
function dl(blob,name){const u=URL.createObjectURL(blob);const a=document.createElement('a');a.href=u;a.download=name;document.body.appendChild(a);a.click();document.body.removeChild(a);URL.revokeObjectURL(u)}
function toast(msg,type){
    const old=$('.toast');if(old)old.remove();
    const t=document.createElement('div');t.className='toast'+(type==='warn'?' toast--warn':type==='err'?' toast--err':'');t.textContent=msg;t.setAttribute('role','alert');
    document.body.appendChild(t);setTimeout(()=>{if(t.parentNode)t.remove()},2700);
}
function esc(s){const d=document.createElement('div');d.appendChild(document.createTextNode(s));return d.innerHTML}

document.addEventListener('DOMContentLoaded',init);
})();
