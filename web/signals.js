(function(root) {
  'use strict';
  const flag = value => value==='YES' || value==='NO' ? value : 'UNKNOWN';
  function score(value) {
    if (value == null || typeof value==='boolean' || String(value).trim()==='') return null;
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
  const api={flag,score,comparisons};
  if (typeof module!=='undefined' && module.exports) module.exports=api;
  else root.IPSignals=api;
})(globalThis);
