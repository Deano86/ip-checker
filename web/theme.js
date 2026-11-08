(function() {
  const presets=['slate','graphite','midnight','forest','light'];
  let palette='slate';
  try {
    const saved=localStorage.getItem('ip-checker-palette');
    if(presets.includes(saved)) palette=saved;
    else if(localStorage.getItem('ip-checker-theme')==='light') palette='light';
  } catch {}
  function apply(value) {
    palette=presets.includes(value)?value:'slate';
    const theme=palette==='light'?'light':'dark';
    document.documentElement.dataset.palette=palette;
    document.documentElement.dataset.theme=theme;
    try {localStorage.setItem('ip-checker-palette',palette); localStorage.setItem('ip-checker-theme',theme);} catch {}
  }
  apply(palette);
  window.IPCheckerTheme={apply};
})();
