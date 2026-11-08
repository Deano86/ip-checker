'use strict';
const form = document.getElementById('login-form'), message = document.getElementById('login-message');
fetch('/api/session').then(r=>r.json()).then(data=> {
  if(data.user && !resetToken && !verifyToken) window.location.replace('/');
  else if(data.setup_required) {
    form.hidden=true;
    message.textContent='First-time setup: create your administrator from the server terminal. See the README account setup instructions.';
  }
}).catch(()=> {message.textContent='Could not connect to the server. Refresh to try again.';});
form.addEventListener('submit', async event=> {
  event.preventDefault(); const button=form.querySelector('button'); button.disabled=true; message.textContent='Signing in…';
  try {
    const response=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:form.elements.username.value,password:form.elements.password.value})});
    const data=await response.json();
    if(!response.ok) throw new Error(data.error || 'Sign-in failed.');
    form.elements.password.value=''; window.location.replace('/');
  } catch(error) {message.textContent=error.message; button.disabled=false;}
});

const fragment=new URLSearchParams(window.location.hash.slice(1));
const resetToken=fragment.get('reset'), verifyToken=fragment.get('verify');
if(resetToken || verifyToken) history.replaceState(null,'','/login');
async function publicPost(path,body) {
  const response=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  const result=await response.json();if(!response.ok) throw new Error(result.error || 'Request failed.');return result;
}
if(resetToken) {form.hidden=true;document.getElementById('reset-form').hidden=false;message.textContent='Choose a new password. Your second-factor protection stays enabled.';}
if(verifyToken) publicPost('/api/verify-email',{token:verifyToken}).then(()=> {message.textContent='Email verified. You can now receive password reset links.';}).catch(error=> {message.textContent=error.message;});
document.getElementById('show-reset').addEventListener('click',()=> {document.getElementById('forgot-form').hidden=false;});
document.getElementById('forgot-form').addEventListener('submit',async event=> {
  event.preventDefault();const button=event.target.querySelector('button');button.disabled=true;
  try {const data=await publicPost('/api/forgot-password',{email:event.target.elements.email.value});message.textContent=data.message;}
  catch(error) {message.textContent=error.message;} finally {button.disabled=false;}
});
document.getElementById('reset-form').addEventListener('submit',async event=> {
  event.preventDefault();const target=event.target,button=target.querySelector('button');
  if(target.elements.password.value!==target.elements.confirm.value) {message.textContent='Passwords do not match.';return;}
  button.disabled=true;
  try {await publicPost('/api/reset-password',{token:resetToken,password:target.elements.password.value});target.reset();target.hidden=true;form.hidden=false;message.textContent='Password reset. Sign in with your new password.';}
  catch(error) {message.textContent=error.message;} finally {button.disabled=false;}
});
