'use strict';
const $ = id => document.getElementById(id);
let rows = [], scanId = null, polling = false, sortKey = 'IP Address', sortDirection = 1;
let riskIP = '';
let currentUser=null, csrfToken='', historyPage=1;
const providers = [
  {name:'IPinfo',logo:'ip',description:'ASN & network ownership'},
  {name:'IP2Location',logo:'i2',description:'Proxy intelligence'},
  {name:'proxycheck.io',logo:'pc',description:'VPN, Tor & hosting'},
  {name:'Spamhaus',logo:'sh',description:'Threat & reputation lists'},
  {name:'IPQS',logo:'iq',description:'Fraud score & abuse · optional'},
  {name:'Kickbox',logo:'kb',description:'Email deliverability & Sendex · optional'},
  {name:'MaxMind GeoLite2',logo:'mm',description:'Local IP geolocation · optional'}
];

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}
function showError(message) { $('error').textContent = message; $('error').hidden = !message; }
async function api(path, options) {
  options={...options,headers:{...(options?.headers || {}),...(options?.method && options.method!=='GET'?{'X-CSRF-Token':csrfToken}:{})}};
  const response = await fetch(path, options);
  if(response.status===401) window.location.replace('/login');
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || 'The server could not complete this request.');
  return data;
}
function setView(view) {
  if(currentUser?.must_change && view!=='account') view='account';
  if(view==='admin' && currentUser?.role!=='admin') view='account';
  ['dashboard','email','domain','providers','guide','history','account','admin'].forEach(name => $(name+'-view').hidden = name !== view);
  document.querySelectorAll('.nav-item').forEach(node => node.classList.toggle('active', node.dataset.view === view));
  $('breadcrumb').textContent = {dashboard:'Overview',email:'Email lookup',domain:'Domain lookup',providers:'Providers',guide:'Quick guide',history:'Saved results',account:'Account',admin:'Administration'}[view];
  if(view==='history') loadHistory();
  if(view==='admin') loadAdmin();
}
document.querySelectorAll('[data-view]').forEach(node => node.addEventListener('click', () => setView(node.dataset.view)));

async function loadConfig() {
  try {
    const config = await api('/api/config');
    $('provider-list').replaceChildren(); $('setup-cards').replaceChildren();
    providers.forEach(provider => {
      const ready = config.providers.find(item => item.name === provider.name)?.configured;
      const isMaxMind=provider.name==='MaxMind GeoLite2';
      const description=provider.description+(isMaxMind?' · '+(config.maxmind?.database_date && config.maxmind.database_date!=='UNKNOWN'?'Database '+config.maxmind.database_date:'Install GeoLite2 City'):'');
      const state = () => { const node = element('span','provider-state '+(ready?'ready':'missing')); node.append(element('i'),document.createTextNode(isMaxMind?(ready?'Database ready':config.maxmind?.status || 'NOT_INSTALLED'):(ready?'Configured':'Key needed'))); return node; };
      const row = element('div','provider-row');
      const name = element('div','provider-name',provider.name); name.append(element('small','',description));
      row.append(element('span','provider-logo',provider.logo),name,state()); $('provider-list').append(row);
      const card = element('article','panel setup-card');
      card.append(element('span','provider-logo',provider.logo),element('h2','',provider.name),element('p','',description),state());
      $('setup-cards').append(card);
    });
    const count = config.providers.filter(provider => provider.configured).length;
    $('provider-summary').textContent = count+' of '+providers.length+' sources configured';
    $('dependency-note').textContent = config.missing_dependencies.length ? 'Missing server dependencies: '+config.missing_dependencies.join(', ')+'. Use the Docker setup or install them before scanning.' : 'All checker dependencies are available on the server.';
    if (config.active_scan && !polling) { scanId = config.active_scan; await poll(); }
    return config;
  } catch (error) {
    $('provider-summary').textContent = 'Server unavailable';
    document.querySelector('.server-pill').textContent = 'Connection unavailable';
    showError(error.message);
    return null;
  }
}
$('refresh-config').addEventListener('click', loadConfig);
function countInput() {
  const values = new Set($('ips').value.split('\n').map(line=>line.split('#')[0].trim()).filter(Boolean));
  $('input-count').textContent = values.size+' address'+(values.size===1?'':'es');
}
$('ips').addEventListener('input',countInput);
$('upload').addEventListener('change',async event => {
  const file = event.target.files[0]; if (!file) return;
  if (file.size > 95000) { showError('Choose a text file smaller than 95 KB.'); return; }
  try { $('ips').value = await file.text(); countInput(); showError(''); }
  catch { showError('Could not read this file. Try a plain text file.'); }
  event.target.value = '';
});
$('scan-form').addEventListener('submit',async event => {
  event.preventDefault(); if (polling) return;
  showError(''); $('run').disabled = true;
  try {
    const result = await api('/api/scans',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ips:$('ips').value})});
    scanId = result.id;
    localStorage.setItem('ip-checker-last-scan-'+currentUser.id,scanId); rows = []; render(); await poll();
  } catch (error) { showError(error.message); $('run').disabled = false; }
});
async function poll() {
  if (polling || !scanId) return;
  polling = true; $('run').disabled = true; $('scan-progress').hidden = false;
  try {
    while (true) {
      const scan = await api('/api/scans/'+scanId);
      rows = scan.rows; render();
      $('progress').value = scan.total ? scan.completed/scan.total*100 : 0;
      $('progress-count').textContent = scan.completed+' / '+scan.total;
      $('progress-label').textContent = scan.status === 'running' ? 'Checking addresses…' : scan.status === 'complete' ? 'Scan complete' : 'Scan stopped';
      $('results-caption').textContent = scan.status === 'running' ? 'Live results · '+scan.completed+' of '+scan.total+' addresses checked' : scan.completed+' addresses checked'+(scan.skipped.length?' · '+scan.skipped.length+' invalid entries skipped':'');
      if (scan.status !== 'running') { if (scan.error) showError(scan.error); break; }
      await new Promise(resolve=>setTimeout(resolve,1000));
    }
  } catch (error) {
    showError(error.message+' Refresh to reconnect to an active scan.');
  } finally { polling = false; $('run').disabled = false; }
}
function badge(value, threat=false) {
  const label = {YES:'Yes',NO:'No',UNKNOWN:'Unknown'}[value] || value;
  return element('span','badge '+(value==='YES'?(threat?'threat':'yes'):value==='NO'?'no':'unknown'),label);
}
function render() {
  renderGauges();
  const counts = {total:rows.length,anon:rows.filter(row=>row.Anonymisation==='YES').length,host:rows.filter(row=>row.Hosting==='YES').length,threat:rows.filter(row=>row['Threat Listing']==='YES').length};
  for (const [key,value] of Object.entries(counts)) { $('count-'+key).textContent=value; $('bar-'+key).style.width=(rows.length?value/rows.length*100:0)+'%'; }
  $('total-caption').textContent = rows.length ? 'In this scan' : 'Ready for your first scan';
  $('row-count').textContent = rows.length;
  $('export').disabled = !rows.length;
  const query = $('search').value.toLowerCase(), filter = $('filter').value;
  let visible = rows.filter(row => Object.values(row).join(' ').toLowerCase().includes(query));
  visible = visible.filter(row => filter==='all' || (filter==='flagged' && !['INCOMPLETE','NO_POSITIVE_DETECTION'].includes(row.Review)) || (filter==='incomplete' && (row.Review==='INCOMPLETE' || row['Lookup Health']==='PARTIAL')) || (filter==='disagreement' && IPSignals.comparisons(row).some(item=>item.disagrees)) || (filter==='negative' && row.Review==='NO_POSITIVE_DETECTION' && row['Lookup Health']!=='PARTIAL'));
  visible.sort((a,b)=>sortDirection*String(a[sortKey]).localeCompare(String(b[sortKey]),undefined,{numeric:true}));
  $('results-body').replaceChildren();
  for (const row of visible) {
    const tr = element('tr');
    tr.append(element('td','ip-cell',row['IP Address']));
    const network = element('td','network-cell',row.Provider); network.append(element('small','',row.ASN+' · '+row.CIDR)); tr.append(network);
    for (const field of ['Anonymisation','Hosting','Threat Listing']) { const td=element('td'); td.append(badge(row[field],field==='Threat Listing')); tr.append(td); }
    const score = row['IPQS Fraud Score'];
    const scoreCell = element('td');
    scoreCell.append(element('span','badge '+(score && score!=='UNKNOWN'?'':'unknown'),score && score!=='UNKNOWN'?score+' / 100':row['IPQS Status']==='NOT_CONFIGURED'?'Not enabled':'Unknown'));
    tr.append(scoreCell);
    const review = element('td');
    const label = row.Review==='NO_POSITIVE_DETECTION'?'No positives':row.Review==='INCOMPLETE'?'Incomplete':row.Review.replaceAll('_',' ').replaceAll('+',' · ');
    review.append(element('span','review-badge '+(row.Review==='NO_POSITIVE_DETECTION'?'negative':row.Review==='INCOMPLETE'?'incomplete':''),label)); if (row['Lookup Health']==='PARTIAL') review.append(element('small','partial-note','Partial provider data')); tr.append(review);
    if (IPSignals.comparisons(row).some(item=>item.disagrees)) review.append(element('small','partial-note','Providers disagree'));
    const detailCell = element('td'); const button = element('button','text-button','↗'); button.setAttribute('aria-label','View details for '+row['IP Address']);
    detailCell.append(button); tr.append(detailCell); tr.addEventListener('click',()=>openDetails(row)); $('results-body').append(tr);
  }
  $('empty').hidden = visible.length>0;
  $('empty').querySelector('h3').textContent = rows.length?'No matching addresses.':'A little context goes a long way.';
  $('empty').querySelector('p').textContent = rows.length?'Try another search or choose a different filter.':'Run a check to uncover the networks and signals behind your IP addresses.';
  $('shown').textContent = 'Showing '+visible.length+' of '+rows.length+' results';
}
function openDetails(row) {
  riskIP=row['IP Address']; renderGauges();
  $('detail-ip').textContent = row['IP Address'];
  const dl=element('dl');
  if (row['Lookup Health']==='PARTIAL') dl.append(element('p','report-notice','Some provider data is unavailable. See provider statuses below; positive detections still apply.'));
  Object.entries(row).forEach(([key,value])=> { const line=element('div','detail-row'); line.append(element('dt','',key),element('dd','',value == null || String(value).trim()==='' ? 'UNKNOWN' : value)); dl.append(line); });
  const comparison=element('section','comparison-panel');
  comparison.append(element('h3','','Provider comparison'),element('p','','Providers use different definitions and datasets. Unknown values are not negative detections.'));
  const table=element('table','comparison-table');
  const head=element('thead'), header=element('tr');
  ['Signal','proxycheck','IP2','IPQS','Comparison'].forEach(label=>header.append(element('th','',label))); head.append(header); table.append(head);
  const body=element('tbody');
  IPSignals.comparisons(row).forEach(item=> {
    const line=element('tr'); line.append(element('td','',item.name));
    [item.pc,item.ip2,item.ipqs].forEach(value=> {const cell=element('td'); cell.append(value===null?element('span','unsupported','—'):badge(value)); line.append(cell);});
    line.append(element('td',item.disagrees?'comparison-warning':'',item.disagrees?'Disagree':item.comparable?'Available agree':'Insufficient data')); body.append(line);
  });
  table.append(body); comparison.append(table);
  comparison.append(element('p','','Active VPN/Tor is shown separately below; it is not the same as suspected VPN/Tor. IP2 does not supply separate VPN/Tor/hosting fields in our current lookup.'));
  const risk=element('section','popup-risk');
  risk.append(element('h3','','Risk & reputation'));
  const gauges=element('div','popup-risk-grid');
  for(const [name,title] of [['detail-ipqs','IPQS fraud risk'],['detail-pc','proxycheck risk']]) {
    const card=element('article','risk-card'); card.append(element('h3','',title));
    const dial=element('div','dial unknown'); dial.id='dial-'+name; dial.setAttribute('role','group'); dial.setAttribute('aria-label',title); dial.setAttribute('aria-valuemin','0'); dial.setAttribute('aria-valuemax','100');
    const inner=element('div','dial-inner');
    const value=element('strong','','—'); value.id='dial-'+name+'-value';
    const caption=element('small','','Unknown'); caption.id='dial-'+name+'-caption';
    inner.append(value,caption); dial.append(element('span','dial-marker'),inner,element('span','dial-min','0'),element('span','dial-max','100'));
    card.append(dial,element('p','','Provider score · 0–100')); gauges.append(card);
  }
  const state=element('article','popup-risk-state'); state.append(element('h3','','Spamhaus reputation'));
  const threat=row['Threat Listing']==='YES';
  state.append(element('strong',threat?'popup-threat':'',threat?'Threat listing detected':row['Spamhaus Status']==='YES'?'Listed: '+row['Spamhaus Lists']:row['Spamhaus Status']==='NO'?'No listing returned':'Unknown'));
  state.append(element('p','','Lists: '+(row['Spamhaus Lists'] || 'UNKNOWN')));
  state.append(element('p','','Review: '+(row.Review || 'UNKNOWN').replaceAll('_',' ').replaceAll('+',' · ')));
  if(row['Lookup Health']==='PARTIAL') state.append(element('span','badge unknown','Partial provider data'));
  gauges.append(state); risk.append(gauges,element('p','risk-footnote','Higher scores mean greater risk within each provider’s model. Scores and listing status are separate signals; a low score does not cancel a threat listing.'));
  const network=element('section','network-summary');
  network.append(element('h3','','Network & location'));
  const facts=element('div','network-facts');
  const known=value=>value && !['UNKNOWN','NOT_PUBLISHED','N/A'].includes(String(value));
  const location=[row.City,row.Region,[row.Country,row['Country Code']].find(known)].filter(known).join(', ') || 'Not returned';
  for(const [title,value,note] of [
    ['Network owner',[row.ASN,row.Provider].filter(known).join(' · ') || 'Unknown','Source: '+(row['Provider Source'] || 'Unknown')],
    ['Approximate location',location,'Source: '+(row['Geolocation Source'] || 'Not present in this saved report')+(row['Geolocation Source']==='MaxMind GeoLite2'?' · Database '+row['MaxMind Database Date']+(known(row['Accuracy Radius km'])?' · Accuracy radius '+row['Accuracy Radius km']+' km':''):'')],
    ['Registered allocation',[row.CIDR,row['Network Name']].filter(known).join(' · ') || 'Unknown','RDAP: '+(row['RDAP Status'] || 'Not present in this saved report')],
    ['Report completeness',row['Lookup Health'] || 'UNKNOWN','Scores and threat/listing results remain separate signals.']
  ]) {const card=element('article');card.append(element('h4','',title),element('strong','',value),element('small','',note));facts.append(card);}
  network.append(facts,element('p','risk-footnote','IP geolocation is approximate and does not identify a person or a precise address. Registered allocation country may differ from geolocation.'));
  if(row['Geolocation Source']==='MaxMind GeoLite2') {
    const attribution=element('p','risk-footnote','This product includes GeoLite2 Data created by MaxMind, available from ');
    const link=element('a','','MaxMind');link.href='https://www.maxmind.com';link.target='_blank';link.rel='noreferrer';attribution.append(link);network.append(attribution);
  }
  $('detail-content').replaceChildren(risk,network,comparison,dl);
  setDial('detail-ipqs',row['IPQS Fraud Score'],row['IPQS Status']==='NOT_CONFIGURED');
  setDial('detail-pc',row['PC Risk']);
  $('details').showModal(); $('detail-content').scrollTop=0;
}
function setDial(name,value,notConfigured=false) {
  const dial=$('dial-'+name), score=IPSignals.score(value);
  const provider=name.includes('pc')?'pc':'ipqs';
  dial.style.setProperty('--low-band-angle',provider==='pc'?'67.5deg':'202.5deg');
  dial.style.setProperty('--high-band-angle',provider==='pc'?'202.5deg':'243deg');
  dial.setAttribute('role',score===null?'group':'meter');
  dial.classList.toggle('unknown',score===null);
  dial.style.setProperty('--needle-angle',(score===null?0:-135+score*2.7)+'deg');
  $('dial-'+name+'-value').textContent=score===null?'—':String(score);
  $('dial-'+name+'-caption').textContent=score===null?(notConfigured?'Not enabled':'Unknown'):'out of 100 · '+IPSignals.riskBand(provider,score);
  dial.setAttribute('aria-valuetext',score===null?'Unknown':score+' out of 100');
  if(score===null) dial.removeAttribute('aria-valuenow'); else dial.setAttribute('aria-valuenow',score);
}
function renderGauges() {
  const select=$('risk-address');
  if (!rows.some(row=>row['IP Address']===riskIP)) riskIP=rows[0]?.['IP Address'] || '';
  select.replaceChildren();
  if (!rows.length) {const option=element('option','','Run a scan to choose an address'); option.value=''; select.append(option);}
  rows.forEach(row=> {const option=element('option','',row['IP Address']); option.value=row['IP Address']; select.append(option);});
  select.value=riskIP; select.disabled=!rows.length;
  const row=rows.find(row=>row['IP Address']===riskIP) || {};
  setDial('ipqs',row['IPQS Fraud Score'],row['IPQS Status']==='NOT_CONFIGURED');
  setDial('pc',row['PC Risk']);
  $('reputation-value').textContent=!rows.length?'Awaiting scan':row['Threat Listing']==='YES'?'Threat listing detected':row['Spamhaus Status']==='YES'?'Listed: '+row['Spamhaus Lists']:row['Spamhaus Status']==='NO'?'No Spamhaus listing':'Unknown';
  $('reputation-value').className=row['Threat Listing']==='YES'?'reputation-threat':row['Spamhaus Status']==='YES'?'reputation-listed':row['Spamhaus Status']==='NO'?'reputation-clear':'reputation-unknown';
  $('reputation-note').textContent=row['Spamhaus Status']==='NO'?'No listing returned. This is not a guarantee of safety.':row['Spamhaus Status']==='YES'?'Check list details before making a decision.':'Reputation needs a successful Spamhaus lookup.';
  for (const [id,key] of [['vpn','IPQS Active VPN'],['tor','IPQS Active Tor'],['connection','IPQS Connection Type']]) {
    const value=row[key]; $('fact-'+id).textContent={YES:'Yes',NO:'No'}[value] || (value && value!=='UNKNOWN'?value:'Unknown');
  }
  const comparison=IPSignals.comparisons(row), conflicts=comparison.filter(item=>item.disagrees);
  $('fact-agreement').textContent=conflicts.length?conflicts.length+' disagreement'+(conflicts.length===1?'':'s'):comparison.some(item=>item.comparable)?'Available signals agree':'Insufficient data';
}
$('risk-address').addEventListener('change',event=> {riskIP=event.target.value; renderGauges();});
$('close-details').addEventListener('click',()=>$('details').close());
$('details').addEventListener('click',event=> {
  if(event.target!==$('details')) return;
  const rect=$('details').getBoundingClientRect();
  if(event.clientX<rect.left || event.clientX>rect.right || event.clientY<rect.top || event.clientY>rect.bottom) $('details').close();
});
$('search').addEventListener('input',render); $('filter').addEventListener('change',render);
document.querySelectorAll('[data-sort]').forEach(button=>button.addEventListener('click',()=> { sortDirection=sortKey===button.dataset.sort?-sortDirection:1; sortKey=button.dataset.sort; render(); }));
$('export').addEventListener('click',()=> {
  if (rows.length && scanId) window.location.href='/api/scans/'+scanId+'/csv';
});
async function init() {
  render(); const config=await loadConfig();
  if (config && !config.active_scan) {
    const last=localStorage.getItem('ip-checker-last-scan-'+currentUser.id);
    if (last && /^[a-f0-9]{32}$/.test(last)) {
      try { const scan=await api('/api/scans/'+last); scanId=last; rows=scan.rows; render(); $('results-caption').textContent='Restored last scan · '+scan.completed+' addresses checked'; }
      catch { localStorage.removeItem('ip-checker-last-scan-'+currentUser.id); }
    }
  }
}
startSession();

$('theme-select').value=document.documentElement.dataset.palette || 'slate';
$('theme-select').addEventListener('change',event=>window.IPCheckerTheme.apply(event.target.value));
let emailResult=null;
function renderEmail(report,saved=false) {
  emailResult=report;
  $('email-report').hidden=false;
  $('email-result-address').textContent=report['Email Address'];
  $('email-result-caption').textContent=(report.Provider || 'IPQS')+' · '+(saved?'Saved report':'Fresh lookup')+(report['Checked At']?' · '+new Date(report['Checked At']).toLocaleString():'');
  $('email-ipqs-card').hidden=report.Provider==='Kickbox';
  $('email-kickbox-card').hidden=!Object.keys(report).some(key=>key.startsWith('Kickbox '));
  setDial('email',report['Fraud Score']);
  const quality=IPSignals.score(report['Kickbox Sendex']);
  const sendex=quality!==null && quality<=1?quality:null;
  const qualityDial=$('dial-kickbox');
  qualityDial.classList.toggle('unknown',sendex===null);
  qualityDial.style.setProperty('--needle-angle',(sendex===null?0:-135+sendex*270)+'deg');
  qualityDial.setAttribute('role',sendex===null?'group':'meter');
  qualityDial.setAttribute('aria-valuetext',sendex===null?'Unknown':sendex+' out of 1; higher is better');
  if(sendex===null) qualityDial.removeAttribute('aria-valuenow'); else qualityDial.setAttribute('aria-valuenow',sendex);
  $('dial-kickbox-value').textContent=sendex===null?'—':String(sendex);
  $('dial-kickbox-caption').textContent=sendex===null?'Unknown':'out of 1 · quality';
  $('kickbox-result').textContent=report['Kickbox Result'] || report['Kickbox Status'] || 'UNKNOWN';
  $('email-partial').hidden=report['Lookup Health']!=='PARTIAL' && report['Catch All']!=='YES' && report['Kickbox Accept All']!=='YES';
  $('email-partial').textContent=report['Lookup Notes'] || 'Some email checks are unavailable. Unknown fields are not negative results.';
  $('email-review').textContent=[report.Review,report['Kickbox Result']?'Kickbox: '+report['Kickbox Result']+' ('+report['Kickbox Reason']+').':''].filter(Boolean).join(' · ') || 'Review the returned fields; a missing value is not a negative detection.';
  $('email-highlights').replaceChildren();
  const highlights=report.Provider==='Kickbox'?['Kickbox Result','Kickbox Disposable','Kickbox Accept All','Kickbox Role']:['Valid','Disposable','Deliverability','Recent Abuse'];
  for(const key of highlights) {
    const box=element('div','email-highlight'); box.append(element('span','',key),element('strong','',report[key] || 'UNKNOWN')); $('email-highlights').append(box);
  }
  $('email-timeout-note').hidden=report['Verification Timed Out']!=='YES';
  $('email-fields').replaceChildren();
  for(const [key,value] of Object.entries(report)) {const line=element('div','detail-row'); line.append(element('dt','',key),element('dd','',value == null || String(value).trim()===''?'UNKNOWN':value)); $('email-fields').append(line);}
}
$('email-form').addEventListener('submit',async event=> {
  event.preventDefault();
  $('email-error').hidden=true; $('email-report').hidden=true; emailResult=null;
  $('email-run').disabled=true; $('email-progress').hidden=false;
  try {
    const result=await api('/api/email',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:$('email-address').value,provider:$('email-provider').value})});
    renderEmail(result.report);
  } catch(error) {$('email-error').textContent=error.message; $('email-error').hidden=false;}
  finally {$('email-run').disabled=false; $('email-progress').hidden=true;}
});
$('email-export').addEventListener('click',()=> {
  if(!emailResult) return;
  const quote=value=>{value=String(value); if(/^[=+@-]/.test(value.trimStart())) value="'"+value; return '"'+value.replaceAll('"','""')+'"';};
  const csv=[Object.keys(emailResult),Object.values(emailResult)].map(row=>row.map(quote).join(',')).join('\r\n');
  const url=URL.createObjectURL(new Blob([csv],{type:'text/csv'})); const link=element('a'); link.href=url; link.download='email-result.csv'; link.click(); setTimeout(()=>URL.revokeObjectURL(url),1000);
});

let domainResult=null;
function renderDomain(result) {
  domainResult=result;
  $('domain-report').hidden=false;
  $('domain-result-name').textContent=result.report.Domain;
  $('domain-partial').hidden=result.health!=='PARTIAL';
  const summary=IPSignals.domainSummary(result.reputation);
  const badgeNode=element('span','badge '+summary.tone,summary.label);
  $('domain-summary').replaceChildren(badgeNode,element('p','',summary.note+' Domain reputation is a listing result, not a numerical fraud score.'));
  $('domain-notes').replaceChildren(...(result.notes || []).map(note=>element('li','',note)));
  $('domain-reputation').replaceChildren();
  for(const check of result.reputation || []) {
    const card=element('article','domain-reputation-card');
    card.append(element('h4','','Spamhaus '+check.list));
    const label=check.listed==='YES'?(check.list==='ZRD'?'Recently observed':'Listed'):check.listed==='NO'?'No listing returned':check.status==='NOT_CONFIGURED'?'Not configured':'Unknown';
    card.append(element('strong',check.listed==='YES'?'domain-listing-positive':'',label));
    card.append(element('p','',check.list==='ZRD'?'Recently observed domain dataset':'Domain block list'));
    card.append(element('span','badge '+(check.listed==='YES'?(check.list==='ZRD'?'yes':'threat'):check.listed==='NO'?'no':'unknown'),check.status.replaceAll('_',' ')));
    if(check.categories.length) card.append(element('p','',check.categories.join(' · ')));
    if(check.codes.length) card.append(element('small','','Return codes: '+check.codes.join(', ')));
    if(check.status==='NOT_CONFIGURED') card.append(element('p','','Add SPAMHAUS_KEY to .secrets to enable this check.'));
    if(check.listed==='UNKNOWN' && check.status!=='NOT_CONFIGURED') card.append(element('p','','Check DQS key access to this dataset and server DNS connectivity.'));
    $('domain-reputation').append(card);
  }
  $('domain-fields').replaceChildren();
  for(const [key,value] of Object.entries(result.report)) {
    const line=element('div','detail-row'); line.append(element('dt','',key),element('dd','',value || 'UNKNOWN')); $('domain-fields').append(line);
  }
  $('domain-query-status').replaceChildren();
  for(const query of result.queries) $('domain-query-status').append(element('span','badge '+(['OK','NO_RECORDS'].includes(query.status)?'no':'unknown'),query.type+' · '+query.status));
  $('domain-records').replaceChildren();
  for(const record of result.records) {const tr=element('tr'); for(const key of ['Type','Name','Value','TTL']) tr.append(element('td','',record[key])); $('domain-records').append(tr);}
  $('domain-empty').hidden=result.records.length>0;
}
$('domain-form').addEventListener('submit',async event=> {
  event.preventDefault();
  $('domain-error').hidden=true; $('domain-report').hidden=true; domainResult=null;
  $('domain-run').disabled=true; $('domain-progress').hidden=false;
  try {renderDomain(await api('/api/domain',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({domain:$('domain-name').value})}));}
  catch(error) {$('domain-error').textContent=error.message; $('domain-error').hidden=false;}
  finally {$('domain-run').disabled=false; $('domain-progress').hidden=true;}
});
$('domain-export').addEventListener('click',()=> {
  if(!domainResult) return;
  const quote=value=>{value=String(value); if(/^[=+@-]/.test(value.trimStart())) value="'"+value; return '"'+value.replaceAll('"','""')+'"';};
  const rows=[['Section','Field / type','Value','TTL (seconds)']];
  Object.entries(domainResult.report).forEach(([key,value])=>rows.push(['Registration',key,value,'']));
  (domainResult.reputation || []).forEach(check=> {
    rows.push(['Spamhaus',check.list+' status',check.status,''],['Spamhaus',check.list+' listed',check.listed,''],['Spamhaus',check.list+' categories',check.categories.join('; '),''],['Spamhaus',check.list+' codes',check.codes.join('; '),'']);
  });
  domainResult.queries.forEach(query=>rows.push(['DNS query',query.type,query.status,'']));
  domainResult.records.forEach(record=>rows.push(['DNS record',record.Type+' '+record.Name,record.Value,record.TTL]));
  const csv=rows.map(row=>row.map(quote).join(',')).join('\r\n');
  const url=URL.createObjectURL(new Blob([csv],{type:'text/csv'})); const link=element('a'); link.href=url; link.download='domain-result.csv'; link.click(); setTimeout(()=>URL.revokeObjectURL(url),1000);
});

async function startSession() {
  try {
    const session=await api('/api/session');
    if(!session.user) {window.location.replace('/login'); return;}
    currentUser=session.user; csrfToken=currentUser.csrf;
    $('account-summary').textContent=currentUser.username+' · '+(currentUser.role==='admin'?'Administrator':'User');
    $('admin-nav').hidden=currentUser.role!=='admin';
    $('history-scope-label').hidden=currentUser.role!=='admin';
    const security=await loadSecurity();
    if(currentUser.must_change) {
      $('password-note').textContent='Change your temporary password before using the workspace. Use 15–128 characters.';
      setView('account');
    } else if(security?.needs_mfa || security?.needs_setup) {setView('account');} else await init();
  } catch(error) {showError(error.message);}
}
const post=(path,data={})=>api(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});
$('sign-out').addEventListener('click',async()=> {
  try {await post('/api/logout'); window.location.replace('/login');} catch(error) {showError(error.message);}
});
$('password-form').addEventListener('submit',async event=> {
  event.preventDefault(); const form=event.target, message=$('account-message');
  if(form.elements.next.value!==form.elements.confirm.value) {message.textContent='New passwords do not match.'; return;}
  const button=form.querySelector('button'); button.disabled=true;
  try {
    await post('/api/password',{current_password:form.elements.current.value,new_password:form.elements.next.value});
    form.reset(); window.location.replace('/login');
  } catch(error) {message.textContent=error.message;} finally {button.disabled=false;}
});
function dateLabel(seconds) {return new Date(seconds*1000).toLocaleString();}
async function loadHistory() {
  $('history-message').textContent='Loading saved results…';
  try {
    const params=new URLSearchParams({q:$('history-query').value,kind:$('history-kind').value,scope:$('history-scope').value,page:String(historyPage)});
    const result=await api('/api/history?'+params);
    $('history-items').replaceChildren();
    for(const item of result.items) {
      const tr=element('tr');
      const owner=element('td','',item.kind.toUpperCase()); owner.append(element('small','history-owner',item.username));
      tr.append(element('td','',dateLabel(item.created)),owner,element('td','history-subject',item.subject),element('td','',item.status));
      const actions=element('td'), open=element('button','text-button','Open ↗'), remove=element('button','text-button','Delete');
      open.addEventListener('click',async()=> {
        if(polling) {$('history-message').textContent='Wait for the current scan to finish before opening another report.'; return;}
        try {
          const saved=await api('/api/history/'+item.id);
          if(saved.kind==='ip') {scanId=item.id; setView('dashboard'); await poll();}
          else if(saved.kind==='email') {renderEmail(saved.payload.report,true); setView('email');}
          else {renderDomain(saved.payload); setView('domain');}
        } catch(error) {$('history-message').textContent=error.message;}
      });
      remove.disabled=item.status==='running';
      remove.addEventListener('click',async()=> {
        if(!window.confirm('Delete this saved result permanently?')) return;
        try {
          await post('/api/history/'+item.id+'/delete');
          if(scanId===item.id) {scanId=null;rows=[];render();localStorage.removeItem('ip-checker-last-scan-'+currentUser.id);}
          await loadHistory();
        } catch(error) {$('history-message').textContent=error.message;}
      });
      actions.append(open,remove);tr.append(actions);$('history-items').append(tr);
    }
    $('history-message').textContent=result.total+' saved result'+(result.total===1?'':'s')+(result.total?'':' · Run a lookup to save your first report.');
    $('history-page').textContent='Page '+historyPage+' of '+Math.max(1,Math.ceil(result.total/50));
    $('history-prev').disabled=historyPage<=1; $('history-next').disabled=historyPage*50>=result.total;
  } catch(error) {$('history-message').textContent=error.message;}
}
$('history-form').addEventListener('submit',event=> {event.preventDefault();historyPage=1;loadHistory();});
$('history-prev').addEventListener('click',()=> {historyPage--;loadHistory();});
$('history-next').addEventListener('click',()=> {historyPage++;loadHistory();});
async function loadAdmin() {
  try {
    const data=await api('/api/admin');$('mfa-policy-form').elements.required.checked=!!data.require_mfa; $('admin-mail-status').textContent=data.mail_configured?'Mail service configured.':'Mail service needs configuration in .mail_secrets.'; $('admin-users').replaceChildren();$('admin-audit').replaceChildren();
    $('retention-form').elements.days.value=data.retention_days;
    $('admin-counts').textContent=Object.entries(data.counts).map(([kind,n])=>kind.toUpperCase()+': '+n).join(' · ') || 'No saved results yet.';
    for(const user of data.users) {
      const tr=element('tr'), actions=element('td'), edit=element('button','text-button','Manage');
      edit.addEventListener('click',()=> {
        const form=$('edit-user-form');form.reset();const profile=data.profiles?.find(p=>p.user_id===user.id);form.elements.email.value=profile?.email || ''; form.elements.require_mfa.checked=!!profile?.required;form.elements.user_id.value=user.id;form.elements.role.value=user.role;form.elements.active.checked=!!user.active;
        $('edit-user-title').textContent='Manage '+user.username;$('edit-user-message').textContent='';$('edit-user').showModal();
      });
      actions.append(edit);tr.append(element('td','',user.username),element('td','',user.role),element('td','',user.active?(user.must_change?'Password change required':'Active'):'Disabled'),actions);$('admin-users').append(tr);
    }
    for(const item of data.audit) {
      const tr=element('tr');for(const value of [dateLabel(item.created),item.username || 'System / anonymous',item.action,item.target]) tr.append(element('td','',value));$('admin-audit').append(tr);
    }
  } catch(error) {$('admin-message').textContent=error.message;}
}
$('create-user-form').addEventListener('submit',async event=> {
  event.preventDefault();const form=event.target, button=form.querySelector('button');button.disabled=true;
  try {
    await post('/api/admin/users',{username:form.elements.username.value,password:form.elements.password.value,role:form.elements.role.value,email:form.elements.email.value,require_mfa:form.elements.require_mfa.checked});
    form.reset();$('admin-message').textContent='Account created. Share the temporary password privately; a change is required at first sign-in.';await loadAdmin();
  } catch(error) {$('admin-message').textContent=error.message;} finally {button.disabled=false;}
});
$('edit-user-form').addEventListener('submit',async event=> {
  event.preventDefault();const form=event.target, button=form.querySelector('button[type="submit"]');button.disabled=true;
  try {
    const data={role:form.elements.role.value,active:form.elements.active.checked,email:form.elements.email.value,require_mfa:form.elements.require_mfa.checked,reset_mfa:form.elements.reset_mfa.checked};
    if(data.reset_mfa && !window.confirm('Reset all authenticators, passkeys and recovery codes for this account? Verify the user identity first.')) return;
    if(form.elements.password.value) data.password=form.elements.password.value;
    const target=Number(form.elements.user_id.value);await post('/api/admin/users/'+target,data);form.reset();$('edit-user').close();
    if(target===currentUser.id) {window.location.replace('/login');return;}
    $('admin-message').textContent='Account updated and existing sessions revoked.';await loadAdmin();
  } catch(error) {$('edit-user-message').textContent=error.message;} finally {button.disabled=false;}
});
$('close-edit-user').addEventListener('click',()=> {$('edit-user-form').reset();$('edit-user').close();});
$('edit-user').addEventListener('close',()=> $('edit-user-form').reset());
$('retention-form').addEventListener('submit',async event=> {
  event.preventDefault();if(!window.confirm('Apply this retention period to all users? Older results and activity will be permanently removed.')) return;
  try {await post('/api/admin/retention',{days:Number(event.target.elements.days.value)});$('admin-message').textContent='Retention updated.';await loadAdmin();}
  catch(error) {$('admin-message').textContent=error.message;}
});

async function loadSecurity() {
  try {
    const state=await api('/api/security/state');
    $('security-summary').textContent=state.needs_mfa?'Verify your second factor to continue.':state.needs_setup?'Your administrator requires two-factor authentication. Enrol an authenticator or passkey to continue.':(state.totp_enabled || state.passkeys.length)?'Two-factor protection is enabled.':'Add an authenticator or passkey to protect your account.';
    $('mfa-check').hidden=!state.needs_mfa;$('security-manage').hidden=state.needs_mfa || !!currentUser.must_change;
    $('account-email').textContent=state.email?'Recovery email: '+state.email+' · '+(state.email_verified?'Verified':'Not verified'):'No recovery email. Ask your administrator to add one.';
    $('verify-account-email').disabled=!state.email || !state.mail_configured || state.email_verified;
    $('start-totp').hidden=state.totp_enabled;$('remove-totp').hidden=!state.totp_enabled;
    $('add-passkey').disabled=!state.passkeys_available;$('verify-passkey').hidden=!state.passkeys.length || !state.passkeys_available;
    $('new-recovery').hidden=!state.totp_enabled && !state.passkeys.length;
    $('passkey-list').replaceChildren();
    for(const key of state.passkeys) {
      const line=element('p','',key.name+' · '+dateLabel(key.created)+' '), remove=element('button','text-button','Remove passkey');
      remove.addEventListener('click',()=> securityAction(async()=> {
        if(!window.confirm('Remove this passkey?')) return;
        await post('/api/security/remove-factor',{password:$('security-password').value,passkey_id:key.id});await loadSecurity();
      }));line.append(remove);$('passkey-list').append(line);
    }
    return state;
  } catch(error) {$('security-message').textContent=error.message;return null;}
}
async function securityAction(action) {
  $('security-message').textContent='';
  try {await action();} catch(error) {$('security-message').textContent=error.message;}
  finally {$('security-password').value='';}
}
function showRecovery(result) {
  if(result.recovery_codes) {$('recovery-result').hidden=false;$('recovery-codes').textContent=result.recovery_codes.join('\n');}
}
$('mfa-form').addEventListener('submit',event=> {event.preventDefault();securityAction(async()=> {await post('/api/security/verify',{code:event.target.elements.code.value});event.target.reset();window.location.replace('/');});});
$('start-totp').addEventListener('click',()=> securityAction(async()=> {
  const result=await post('/api/security/totp-start',{password:$('security-password').value});$('totp-qr').src=result.qr;$('totp-secret').textContent=result.secret;$('totp-setup').hidden=false;
}));
$('totp-confirm').addEventListener('submit',event=> {event.preventDefault();securityAction(async()=> {
  const result=await post('/api/security/totp-confirm',{code:event.target.elements.code.value});event.target.reset();$('totp-setup').hidden=true;$('totp-qr').removeAttribute('src');$('totp-secret').textContent='';showRecovery(result);await loadSecurity();$('security-message').textContent='Authenticator enabled. Save the recovery codes below, then return to Overview.';
});});
$('remove-totp').addEventListener('click',()=> securityAction(async()=> {if(!window.confirm('Remove authenticator protection?')) return;await post('/api/security/remove-factor',{password:$('security-password').value});await loadSecurity();}));
$('new-recovery').addEventListener('click',()=> securityAction(async()=> {if(!window.confirm('Replace all existing recovery codes?')) return;showRecovery(await post('/api/security/recovery-codes',{password:$('security-password').value}));}));
$('hide-recovery').addEventListener('click',()=> {$('recovery-result').hidden=true;$('recovery-codes').textContent='';window.location.replace('/');});
$('verify-account-email').addEventListener('click',()=> securityAction(async()=> {await post('/api/security/verify-email',{password:$('security-password').value});$('security-message').textContent='Verification email queued. Open the link in your inbox.';}));
function decodeCredential(value) {return Uint8Array.from(atob(value.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0));}
function encodeCredential(buffer) {return btoa(String.fromCharCode(...new Uint8Array(buffer))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');}
async function usePasskey(register) {
  if(!window.PublicKeyCredential || !window.isSecureContext) throw new Error('Passkeys require HTTPS or localhost and a compatible browser.');
  const start=await post('/api/security/'+(register?'passkey-register-options':'passkey-options'),{password:$('security-password').value});
  const options=start.options;options.challenge=decodeCredential(options.challenge);
  if(options.user) options.user.id=decodeCredential(options.user.id);
  for(const name of ['allowCredentials','excludeCredentials']) if(options[name]) options[name]=options[name].map(item=>({...item,id:decodeCredential(item.id)}));
  const credential=await navigator.credentials[register?'create':'get']({publicKey:options});
  const response={clientDataJSON:encodeCredential(credential.response.clientDataJSON)};
  if(register) {response.attestationObject=encodeCredential(credential.response.attestationObject);response.transports=credential.response.getTransports?.() || [];}
  else {response.authenticatorData=encodeCredential(credential.response.authenticatorData);response.signature=encodeCredential(credential.response.signature);response.userHandle=credential.response.userHandle?encodeCredential(credential.response.userHandle):null;}
  const result=await post('/api/security/'+(register?'passkey-register':'passkey-verify'),{challenge_id:start.challenge_id,name:'Passkey '+new Date().toLocaleDateString(),credential:{id:credential.id,rawId:encodeCredential(credential.rawId),type:credential.type,response,clientExtensionResults:credential.getClientExtensionResults()}});
  if(register) {showRecovery(result);await loadSecurity();$('security-message').textContent='Passkey enrolled. Save any recovery codes below.';} else window.location.replace('/');
}
$('add-passkey').addEventListener('click',()=> securityAction(()=>usePasskey(true)));
$('verify-passkey').addEventListener('click',()=> securityAction(()=>usePasskey(false)));
window.addEventListener('pageshow',event=> {if(event.persisted) window.location.reload();});
$('mfa-policy-form').addEventListener('submit',async event=> {
  event.preventDefault();if(!window.confirm('Apply this two-factor requirement to every user immediately?')) return;
  try {await post('/api/admin/mfa-policy',{required:event.target.elements.required.checked});$('admin-message').textContent='Authentication policy updated.';await loadAdmin();}
  catch(error) {$('admin-message').textContent=error.message;}
});
