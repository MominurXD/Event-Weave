const $ = id => document.getElementById(id);
let currentCase = null;

async function api(path, options={}){
  const res = await fetch(path, options);
  const body = await res.json().catch(()=>({}));
  if(!res.ok) throw new Error(body.detail || 'Request failed');
  return body;
}
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const fmtTime=s=>new Date(s).toLocaleString('en-GB',{day:'2-digit',month:'short',hour:'2-digit',minute:'2-digit',second:'2-digit',timeZone:'UTC'})+' UTC';

function toast(){const t=$('toast');t.classList.add('show');clearTimeout(window.__toast);window.__toast=setTimeout(()=>t.classList.remove('show'),2200)}

function renderCase(c){
  currentCase=c;
  const s=c.summary;
  $('hero-events').textContent=s.event_count;
  $('hero-findings').textContent=s.finding_count;
  $('hero-risk').textContent=s.high_risk_count;
  $('metric-events').textContent=s.event_count;
  $('metric-findings').textContent=s.finding_count;
  $('metric-high').textContent=s.high_risk_count;
  $('metric-evidence').textContent=s.evidence_count;
  $('case-id').textContent='CASE / '+c.case_id.slice(0,8).toUpperCase();
  $('case-title').textContent=c.name;
  $('case-range').textContent=s.first_event ? `${fmtTime(s.first_event)} → ${fmtTime(s.last_event)}` : 'No events';
  $('hash-value').textContent=c.evidence[0]?.sha256 || '—';
  const badge=$('risk-badge');
  badge.textContent=s.high_risk_count>=2?'HIGH RISK':s.finding_count?'REVIEW':'CLEAR';
  badge.className='risk-badge '+(s.high_risk_count>=3?'critical':s.high_risk_count?'high':'neutral');
  renderTimeline(c.events); renderFindings(c.findings); renderGraph(c.entity_links); loadAudit(); toast();
}

function renderTimeline(events){
  $('timeline').innerHTML=events.map(e=>`<div class="timeline-item"><time>${fmtTime(e.timestamp)}</time><span class="timeline-dot"></span><div><b>${esc(e.event_type)} · ${esc(e.action||'observed')}</b><p>${esc(e.source)}${e.actor?' · '+esc(e.actor):''}${e.host?' · '+esc(e.host):''}${e.ip?' · '+esc(e.ip):''}</p><code>${esc(e.details||e.file_path||e.process||'')}</code></div></div>`).join('') || '<p class="empty">No events.</p>';
}
function renderFindings(findings){
  const rank={critical:4,high:3,medium:2,low:1,info:0};
  findings=[...findings].sort((a,b)=>rank[b.severity]-rank[a.severity]);
  $('findings').innerHTML=findings.map(f=>`<div class="finding"><div class="finding-head"><b>${esc(f.title)}</b><span class="severity ${esc(f.severity)}">${esc(f.severity.toUpperCase())}</span></div><p>${esc(f.summary)}</p><small>${esc(f.rule_id)} · ${esc(f.entities.join(' · '))}</small></div>`).join('') || '<p class="empty">No findings.</p>';
}

function renderGraph(links){
  const canvas=$('graph'), ctx=canvas.getContext('2d');
  const rect=canvas.getBoundingClientRect(), dpr=window.devicePixelRatio||1;
  canvas.width=Math.max(620,Math.floor(rect.width*dpr)); canvas.height=Math.floor(300*dpr); ctx.scale(dpr,dpr);
  const w=canvas.width/dpr,h=canvas.height/dpr; ctx.clearRect(0,0,w,h);
  const names=[...new Set(links.flatMap(l=>[l.source,l.target]))].slice(0,18);
  if(!names.length){ctx.fillStyle='#8b9b96';ctx.font='12px system-ui';ctx.fillText('Load a case to draw entity relationships.',20,35);return;}
  const pos={}; names.forEach((n,i)=>{const a=(Math.PI*2*i/names.length)-Math.PI/2;const r=Math.min(w,h)*.36;pos[n]={x:w/2+Math.cos(a)*r,y:h/2+Math.sin(a)*r}});
  ctx.lineWidth=1; links.forEach(l=>{if(!pos[l.source]||!pos[l.target])return;ctx.strokeStyle='rgba(74,118,104,.24)';ctx.beginPath();ctx.moveTo(pos[l.source].x,pos[l.source].y);ctx.lineTo(pos[l.target].x,pos[l.target].y);ctx.stroke()});
  names.forEach((n,i)=>{const p=pos[n];ctx.fillStyle=i%4===0?'#c6ef9a':'#dfeae1';ctx.beginPath();ctx.arc(p.x,p.y,9,0,Math.PI*2);ctx.fill();ctx.strokeStyle='#6b8a80';ctx.stroke();ctx.fillStyle='#29483e';ctx.font='10px system-ui';ctx.fillText(n.slice(0,24),p.x+13,p.y+3)});
}
async function loadAudit(){
  try{const rows=await api('/api/audit');$('audit').innerHTML=rows.slice(0,8).map(r=>`<div class="audit-item"><time>${new Date(r.created_at).toLocaleString('en-GB',{day:'2-digit',month:'short',hour:'2-digit',minute:'2-digit'})}</time><div><b>${esc(r.action)}</b><p>${esc(r.detail)}</p></div></div>`).join('')||'<p class="empty">No audit records.</p>'}catch(e){$('audit').innerHTML='<p class="empty">Audit unavailable.</p>'}
}

$('demo-btn').onclick=async()=>{const b=$('demo-btn');b.disabled=true;b.textContent='Reconstructing…';try{renderCase(await api('/api/demo',{method:'POST'}))}catch(e){alert(e.message)}finally{b.disabled=false;b.innerHTML='Load incident demo <span>→</span>'}};
$('evidence-file').onchange=async e=>{const file=e.target.files?.[0];if(!file)return;const fd=new FormData();fd.append('case_name',$('case-name').value||'Imported Investigation');fd.append('evidence',file);try{renderCase(await api('/api/cases/import',{method:'POST',body:fd}))}catch(err){alert(err.message)}e.target.value=''};
window.addEventListener('resize',()=>currentCase&&renderGraph(currentCase.entity_links));
loadAudit();
if(new URLSearchParams(location.search).get('demo')==='1'){ $('demo-btn').click(); }
