(function() {
  let theme='dark';
  try {const saved=localStorage.getItem('ip-checker-theme'); if(saved==='light'||saved==='dark') theme=saved;} catch {}
  document.documentElement.dataset.theme=theme;
})();
