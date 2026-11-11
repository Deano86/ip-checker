const test=require('node:test');
const assert=require('node:assert/strict');
const {score,comparisons,riskBand,domainSummary}=require('../web/signals.js');
test('unavailable and malformed scores never become zero',()=> {
  for(const value of [null,undefined,'',' ','UNKNOWN','N/A',false,-1,101,'bad']) assert.equal(score(value),null);
  assert.equal(score('0'),0); assert.equal(score('75'),75); assert.equal(score('33.5'),33.5);
});
test('known positive and negative signals disagree',()=> {
  const rows=comparisons({'PC VPN':'NO','IPQS VPN':'YES'});
  assert.equal(rows[0].disagrees,true);
});
test('unknown or unsupported fields do not count as negative votes',()=> {
  const row=comparisons({'PC VPN':'NO','IPQS VPN':'UNKNOWN'})[0];
  assert.equal(row.disagrees,false); assert.equal(row.comparable,false); assert.equal(row.ip2,null);
});
test('anonymity comparison accounts for VPNs rather than only proxy flag',()=> {
  const row=comparisons({'PC VPN':'YES','PC Proxy':'NO','IPQS Proxy':'YES','IP2 Proxy':'YES'})[1];
  assert.equal(row.pc,'YES'); assert.equal(row.disagrees,false); assert.equal(row.comparable,true);
});
test('missing anonymity signals stay unknown',()=> {
  assert.equal(comparisons({'PC Proxy':'NO'})[1].pc,'UNKNOWN');
});
test('connection type compares hosting without treating missing fields as residential',()=> {
  assert.equal(comparisons({'PC Hosting':'YES','IPQS Connection Type':'Residential'})[3].disagrees,true);
  assert.equal(comparisons({'PC Hosting':'YES','IPQS Connection Type':'UNKNOWN'})[3].comparable,false);
});

test('score bands follow each provider model and invalid inputs remain unknown',()=> {
  assert.equal(riskBand('ipqs',74),'Lower');assert.equal(riskBand('ipqs',75),'Elevated');assert.equal(riskBand('ipqs',90),'High');
  assert.equal(riskBand('pc',25),'Lower');assert.equal(riskBand('pc',26),'Elevated');assert.equal(riskBand('pc',76),'High');
  assert.equal(riskBand('pc','UNKNOWN'),null);
  for(const value of [[75],{},'0x64','Infinity']) assert.equal(score(value),null);
  assert.equal(score('1e2'),100);
});

test('domain reputation distinguishes listing, recent observation and incomplete data',()=> {
  assert.equal(domainSummary([{list:'DBL',status:'OK',listed:'YES'}]).tone,'threat');
  assert.equal(domainSummary([{list:'ZRD',status:'OK',listed:'YES'}]).label,'Recently observed domain');
  assert.equal(domainSummary([{list:'DBL',status:'OK',listed:'NO'},{list:'ZRD',status:'TIMEOUT',listed:'UNKNOWN'}]).tone,'unknown');
  assert.equal(domainSummary([{list:'DBL',status:'OK',listed:'NO'},{list:'ZRD',status:'OK',listed:'NO'}]).tone,'no');
});
