(function(root) {
  'use strict';
  const flag = value => value==='YES' || value==='NO' ? value : 'UNKNOWN';
  function score(value) {
    if (!['number','string'].includes(typeof value) || String(value).trim()==='') return null;
    if(typeof value==='string' && !/^(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?$/.test(value.trim())) return null;
    const result=Number(value);
    return Number.isFinite(result) && result>=0 && result<=100 ? result : null;
  }
  function comparisons(row) {
    const pcSignals=['PC Anonymous','PC VPN','PC Proxy','PC Tor'].map(key=>flag(row[key]));
    const pcAnon=pcSignals.includes('YES')?'YES':pcSignals.every(value=>value==='NO')?'NO':'UNKNOWN';
    const connection=String(row['IPQS Connection Type'] || '').toLowerCase();
    const qsHosting=connection==='data center'?'YES':['residential','corporate','education','mobile'].includes(connection)?'NO':'UNKNOWN';
    return [
      {name:'VPN',pc:flag(row['PC VPN']),ip2:null,ipqs:flag(row['IPQS VPN'])},
      {name:'Proxy / anonymity',pc:pcAnon,ip2:flag(row['IP2 Proxy']),ipqs:flag(row['IPQS Proxy'])},
      {name:'Tor',pc:flag(row['PC Tor']),ip2:null,ipqs:flag(row['IPQS Tor'])},
      {name:'Hosting',pc:flag(row['PC Hosting']),ip2:null,ipqs:qsHosting}
    ].map(item=> {
      const known=[item.pc,item.ip2,item.ipqs].filter(value=>value==='YES'||value==='NO');
      return {...item,disagrees:known.includes('YES')&&known.includes('NO'),comparable:known.length>=2};
    });
  }
  function riskBand(provider,value) {
    const number=score(value);if(number===null) return null;
    if(provider==='pc') return number>75?'High':number>25?'Elevated':'Lower';
    return number>=90?'High':number>=75?'Elevated':'Lower';
  }
  function domainSummary(checks) {
    checks=Array.isArray(checks)?checks:[];
    if(checks.some(check=>check.list==='DBL' && check.status==='OK' && check.listed==='YES')) return {label:'Listed in Spamhaus DBL',tone:'threat',note:'Review the returned domain-reputation categories below.'};
    if(checks.some(check=>check.list==='ZRD' && check.status==='OK' && check.listed==='YES')) return {label:'Recently observed domain',tone:'yes',note:'ZRD is an age signal, not a malware verdict.'};
    if(['DBL','ZRD'].every(list=>checks.some(check=>check.list===list && check.status==='OK' && check.listed==='NO'))) return {label:'No domain listing returned',tone:'no',note:'Both domain checks completed. No listing does not guarantee safety.'};
    return {label:'Domain reputation incomplete',tone:'unknown',note:'One or more reputation checks did not return usable data.'};
  }
  const api={flag,score,comparisons,riskBand,domainSummary};
  if (typeof module!=='undefined' && module.exports) module.exports=api;
  else root.IPSignals=api;
})(globalThis);
