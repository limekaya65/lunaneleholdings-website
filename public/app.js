const form=document.getElementById('enquiry'),status=document.getElementById('status');
form.addEventListener('submit',async e=>{
  e.preventDefault();
  const d=Object.fromEntries(new FormData(form));
  status.className='';
  if(!d.name.trim()||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(d.email)||d.message.trim().length<10){
    status.className='err';status.textContent='Please add your name, a valid email and a short message.';return;
  }
  const btn=form.querySelector('button');btn.disabled=true;btn.textContent='Sending…';
  try{
    const r=await fetch('/api/enquiry',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(d)});
    if(!r.ok)throw new Error();
    form.innerHTML='<div class="ok"><h3>Thank you, we have your message.</h3><p class="lead" style="margin:0 auto">A principal will reply within five business days.</p></div>';
  }catch(_){
    btn.disabled=false;btn.textContent='Send enquiry →';
    status.className='err';
    status.innerHTML='Sorry, that didn\'t go through. Please <a href="https://wa.me/27634195979" target="_blank" rel="noopener">WhatsApp us</a> or email <a href="mailto:relations@lunaneleholdings.com">relations@lunaneleholdings.com</a>.';
  }
});
