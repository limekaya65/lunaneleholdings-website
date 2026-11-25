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
    window.lhTrack&&lhTrack('generate_lead',{topic:d.topic});
    form.innerHTML='<div class="ok"><h3>Thank you, we have your message.</h3><p class="lead" style="margin:0 auto">A principal will reply within five business days.</p></div>';
  }catch(_){
    btn.disabled=false;btn.textContent='Send enquiry →';
    status.className='err';
    status.innerHTML='Sorry, that didn\'t go through. Please <a href="https://wa.me/27634195979" target="_blank" rel="noopener">WhatsApp us</a> or email <a href="mailto:relations@lunaneleholdings.com">relations@lunaneleholdings.com</a>.';
  }
});

// ---- Google Analytics 4 (opt-in, POPIA) ----
// Turned on only when <meta name="ga4-id"> holds a G- ID AND the visitor clicks Allow.
(function(){
  const id=(document.querySelector('meta[name="ga4-id"]')||{}).content||'';
  const bar=document.getElementById('consent'),reset=document.getElementById('consent-reset');
  const KEY='lh-analytics';
  const get=()=>{try{return localStorage.getItem(KEY)}catch(_){return null}};
  const set=v=>{try{localStorage.setItem(KEY,v)}catch(_){}};
  window.dataLayer=window.dataLayer||[];
  window.gtag=function(){dataLayer.push(arguments)};
  let loaded=false;
  function load(){
    if(loaded||!/^G-[A-Z0-9]+$/.test(id))return;loaded=true;
    gtag('consent','default',{ad_storage:'denied',ad_user_data:'denied',ad_personalization:'denied',analytics_storage:'granted'});
    const s=document.createElement('script');s.async=true;s.src='https://www.googletagmanager.com/gtag/js?id='+id;document.head.appendChild(s);
    gtag('js',new Date());gtag('config',id,{anonymize_ip:true});
  }
  // Lead events (mark these as key events in GA4). No personal details are sent.
  window.lhTrack=function(name,params){if(loaded)gtag('event',name,params||{})};
  document.addEventListener('click',e=>{
    const a=e.target.closest&&e.target.closest('a');if(!a)return;
    if(a.href.startsWith('https://wa.me/'))lhTrack('whatsapp_click');
    else if(a.href.startsWith('mailto:'))lhTrack('email_click');
    else if(a.href.includes('tech.lunaneleholdings.com/products'))lhTrack('product_click',{product:a.textContent.trim().slice(0,60)});
  });
  if(!/^G-[A-Z0-9]+$/.test(id)){if(reset)reset.parentNode.removeChild(reset);return;}
  if(get()==='yes')load();else if(get()!=='no'&&bar)bar.hidden=false;
  bar&&bar.addEventListener('click',e=>{const v=e.target.dataset&&e.target.dataset.consent;if(!v)return;set(v);bar.hidden=true;if(v==='yes')load();});
  reset&&reset.addEventListener('click',e=>{e.preventDefault();set('');if(bar)bar.hidden=false;});
})();
