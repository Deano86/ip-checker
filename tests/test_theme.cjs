const test=require('node:test');
const assert=require('node:assert/strict');
const vm=require('node:vm');
const fs=require('node:fs');
const source=fs.readFileSync(require('node:path').join(__dirname,'../web/theme.js'),'utf8');
function boot(saved={},blocked=false){
  const values=new Map(Object.entries(saved));
  const context={document:{documentElement:{dataset:{}}},window:{},localStorage:{getItem(key){if(blocked) throw Error('blocked');return values.get(key);},setItem(key,value){if(blocked) throw Error('blocked');values.set(key,value);}}};
  vm.runInNewContext(source,context);
  return {context,values};
}
test('first visit uses subdued Slate dark mode',()=> {
  const {context}=boot(); assert.equal(context.document.documentElement.dataset.theme,'dark'); assert.equal(context.document.documentElement.dataset.palette,'slate');
});
test('all dark palettes stay dark and remember selection',()=> {
  for(const palette of ['slate','graphite','midnight','forest']){
    const {context,values}=boot(); context.window.IPCheckerTheme.apply(palette);
    assert.equal(context.document.documentElement.dataset.theme,'dark'); assert.equal(values.get('ip-checker-palette'),palette);
    assert.equal(boot(Object.fromEntries(values)).context.document.documentElement.dataset.palette,palette);
  }
});
test('existing light preference remains optional and is preserved',()=> {
  assert.equal(boot({'ip-checker-theme':'light'}).context.document.documentElement.dataset.theme,'light');
});
test('invalid preferences and disabled storage fall back safely',()=> {
  assert.equal(boot({'ip-checker-palette':'invalid'}).context.document.documentElement.dataset.palette,'slate');
  const {context}=boot({},true);context.window.IPCheckerTheme.apply('forest');assert.equal(context.document.documentElement.dataset.palette,'forest');
});
