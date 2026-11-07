'use strict';
const $ = id => document.getElementById(id);
let rows = [], scanId = null, polling = false, sample = false, sortKey = 'IP Address', sortDirection = 1;
let riskIP = '';
const providers = [
  {name:'IPinfo',logo:'ip',description:'ASN & network ownership'},
  {name:'IP2Location',logo:'i2',description:'Proxy intelligence'},
  {name:'proxycheck.io',logo:'pc',description:'VPN, Tor & hosting'},
  {name:'Spamhaus',logo:'sh',description:'Threat & reputation lists'},
  {name:'IPQS',logo:'iq',description:'Fraud score & abuse · optional'}
];

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}
function showError(message) { $('error').textContent = message; $('error').hidden = !message; }
async function api(path, options) {
  const response = await fetch(path, options);
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || 'The server could not complete this request.');
  return data;
}
function setView(view) {
  ['dashboard','providers','guide'].forEach(name => $(name+'-view').hidden = name !== view);
  document.querySelectorAll('.nav-item').forEach(node => node.classList.toggle('active', node.dataset.view === view));
  $('breadcrumb').textContent = {dashboard:'Overview',providers:'Providers',guide:'Quick guide'}[view];
}
document.querySelectorAll('[data-view]').forEach(node => node.addEventListener('click', () => setView(node.dataset.view)));

async function loadConfig() {
  try {
    const config = await api('/api/config');
    $('provider-list').replaceChildren(); $('setup-cards').replaceChildren();
    providers.forEach(provider => {
      const ready = config.providers.find(item => item.name === provider.name)?.configured;
      const state = () => { const node = element('span','provider-state '+(ready?'ready':'missing')); node.append(element('i'),document.createTextNode(ready?'Configured':'Key needed')); return node; };
      const row = element('div','provider-row');
      const name = element('div','provider-name',provider.name); name.append(element('small','',provider.description));
      row.append(element('span','provider-logo',provider.logo),name,state()); $('provider-list').append(row);
      const card = element('article','panel setup-card');
      card.append(element('span','provider-logo',provider.logo),element('h2','',provider.name),element('p','',provider.description),state());
      $('setup-cards').append(card);
    });
    const count = config.providers.filter(provider => provider.configured).length;
    $('provider-summary').textContent = count+' of '+providers.length+' keys configured';
    $('dependency-note').textContent = config.missing_dependencies.length ? 'Missing server dependencies: '+config.missing_dependencies.join(', ')+'. Use the Docker setup or install them before scanning.' : 'All checker dependencies are available on the server.';
    if (config.active_scan && !polling) { scanId = config.active_scan; sample = false; await poll(); }
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
    sample = false; $('sample-banner').hidden = true; scanId = result.id;
    localStorage.setItem('ip-checker-last-scan',scanId); rows = []; render(); await poll();
  } catch (error) { showError(error.message); $('run').disabled = false; }
});
async function poll() {
  if (polling || !scanId) return;
  polling = true; $('run').disabled = true; $('sample').disabled = true; $('scan-progress').hidden = false;
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
  } finally { polling = false; $('run').disabled = false; $('sample').disabled = false; }
}
function badge(value, threat=false) {
  const label = {YES:'Yes',NO:'No',UNKNOWN:'Unknown'}[value] || value;
  return element('span','badge '+(value==='YES'?(threat?'threat':'yes'):value==='NO'?'no':'unknown'),label);
}
function render() {
  renderGauges();
  const counts = {total:rows.length,anon:rows.filter(row=>row.Anonymisation==='YES').length,host:rows.filter(row=>row.Hosting==='YES').length,threat:rows.filter(row=>row['Threat Listing']==='YES').length};
  for (const [key,value] of Object.entries(counts)) { $('count-'+key).textContent=value; $('bar-'+key).style.width=(rows.length?value/rows.length*100:0)+'%'; }
  $('total-caption').textContent = rows.length ? (sample?'Illustrative sample scan':'In this scan') : 'Ready for your first scan';
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
  if (row['Lookup Health']==='PARTIAL') dl.append(element('p','error','Some provider data is unavailable. See provider statuses below; positive detections still apply.'));
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
  $('detail-content').replaceChildren(comparison,dl); $('details').showModal();
}
function setDial(name,value,notConfigured=false) {
  const dial=$('dial-'+name), score=IPSignals.score(value);
  dial.setAttribute('role',score===null?'group':'meter');
  dial.classList.toggle('unknown',score===null);
  dial.style.setProperty('--needle-angle',(score===null?0:-135+score*2.7)+'deg');
  $('dial-'+name+'-value').textContent=score===null?'—':String(score);
  $('dial-'+name+'-caption').textContent=score===null?(notConfigured?'Not enabled':'Unknown'):'out of 100';
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
$('details').addEventListener('click',event=> { if(event.target===$('details') && event.clientX < $('details').getBoundingClientRect().left) $('details').close(); });
$('search').addEventListener('input',render); $('filter').addEventListener('change',render);
document.querySelectorAll('[data-sort]').forEach(button=>button.addEventListener('click',()=> { sortDirection=sortKey===button.dataset.sort?-sortDirection:1; sortKey=button.dataset.sort; render(); }));
$('export').addEventListener('click',()=> {
  if (!rows.length) return;
  if (!sample && scanId) { window.location.href='/api/scans/'+scanId+'/csv'; return; }
  const quote = value => '"'+String(value).replaceAll('"','""')+'"';
  const csv = [Object.keys(rows[0]),...rows.map(Object.values)].map(row=>row.map(quote).join(',')).join('\r\n');
  const url=URL.createObjectURL(new Blob([csv],{type:'text/csv'})); const link=element('a'); link.href=url; link.download='sample-ip-results.csv'; link.click(); setTimeout(()=>URL.revokeObjectURL(url),1000);
});
function sampleRow(ip,provider,asn,cidr,flags={}) {
  return {'IP Address':ip,CIDR:cidr,ASN:asn,Provider:provider,'IP2 Proxy':'NO','PC Anonymous':'NO','PC VPN':'NO','PC Proxy':'NO','PC Tor':'NO','PC Hosting':'NO','PC Network Type':'Residential','PC Risk':'0','PC Confidence':'95','Spamhaus Lists':'NONE','Spamhaus Status':'NO',Anonymisation:'NO',Hosting:'NO','Threat Listing':'NO',Review:'NO_POSITIVE_DETECTION','IPQS Status':'OK','IPQS Fraud Score':'0','IPQS Proxy':'NO','IPQS VPN':'NO','IPQS Tor':'NO','IPQS Recent Abuse':'NO','IPQS Bot':'NO',...flags};
}
$('sample').addEventListener('click',()=> {
  sample=true; scanId=null; $('sample-banner').hidden=false; $('scan-progress').hidden=true; showError('');
  rows=[
    sampleRow('203.0.113.10','Example cloud network','AS64500','203.0.113.0/24',{Hosting:'YES','PC Hosting':'YES','PC Network Type':'Hosting',Review:'HOSTING'}),
    sampleRow('203.0.113.20','Example datacenter','AS64501','203.0.113.0/24',{Hosting:'YES','PC Hosting':'YES','PC Network Type':'Hosting',Review:'HOSTING'}),
    sampleRow('203.0.113.30','Example VPN network','AS64502','203.0.113.0/24',{'PC VPN':'YES','PC Anonymous':'YES','IP2 Proxy':'YES',Anonymisation:'YES','PC Risk':'85',Review:'VPN+PROXY'}),
    sampleRow('203.0.113.40','Example residential network','AS64503','203.0.113.0/24'),
    sampleRow('203.0.113.50','Example listed network','AS64504','203.0.113.0/24',{'Spamhaus Lists':'SBL','Spamhaus Status':'YES','Threat Listing':'YES',Review:'SPAMHAUS_THREAT'}),
    sampleRow('203.0.113.60','Example unavailable source','AS64505','203.0.113.0/24',{'PC Anonymous':'UNKNOWN','PC VPN':'UNKNOWN',Anonymisation:'UNKNOWN',Review:'INCOMPLETE'})
  ];
  rows=rows.map((row,index)=>({...row,'IPQS Active VPN':index===2?'YES':'NO','IPQS Active Tor':'NO','IPQS Connection Type':index<2?'Data Center':'Residential','IPQS Abuse Frequency':'none','IPQS Verified Crawler':'NO','IPQS Hostname':'example.test','IPQS Country':'GB',...(index===2?{'PC VPN':'NO','PC Anonymous':'NO','PC Risk':'33','IPQS Fraud Score':'75','IPQS VPN':'YES','IPQS Proxy':'YES'}:{})}));
  $('results-caption').textContent='Illustrative sample · Not live provider data'; render();
});
$('clear-sample').addEventListener('click',()=> { sample=false; rows=[]; $('sample-banner').hidden=true; $('results-caption').textContent='Your next investigation starts here.'; render(); });
async function init() {
  render(); const config=await loadConfig();
  if (config && !config.active_scan) {
    const last=localStorage.getItem('ip-checker-last-scan');
    if (last && /^[a-f0-9]{32}$/.test(last)) {
      try { const scan=await api('/api/scans/'+last); scanId=last; rows=scan.rows; render(); $('results-caption').textContent='Restored last scan · '+scan.completed+' addresses checked'; }
      catch { localStorage.removeItem('ip-checker-last-scan'); }
    }
  }
}
init();
