// Link de empresa/liga (pollaprodes.ar/codigo): arma la vista previa de WhatsApp EN EL MOMENTO con los datos actuales.
// Así un cambio de código, nombre o logo se ve enseguida, sin esperar que se regeneren las páginas.
// Estos datos son los mismos que ya usa la app en el navegador (públicos).
const API="https://vznmqqdxfgqcnncbazvx.supabase.co/functions/v1/api",ANON="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InZ6bm1xcWR4ZmdxY25uY2JhenZ4Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3OTA4OTI1NzksImV4cCI6MjEwNjQ2ODU3OX0.fGXI7Cp2UgcoMlAJVUgMKnkxOK73Nv_rxrBS8CcXzE8",SECRET="PP2026-e45d713bae82f7a471245b7dae206f3b";
const esc=(t)=>String(t||"").replace(/[&<>"]/g,(c)=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
export async function onRequest(ctx){
  const {request,env,params}=ctx;
  const cod=String(params.codigo||"");
  if(!/^[A-Za-z0-9_-]{3,16}$/.test(cod)) return env.ASSETS.fetch(request);
  let emp=null;
  try{
    const r=await fetch(API,{method:"POST",headers:{"Content-Type":"application/json","Authorization":"Bearer "+ANON},body:JSON.stringify({action:"getEmpresaPublica",apiSecret:SECRET,codigo:cod})});
    const j=await r.json(); if(j&&j.ok) emp=j.empresa;
  }catch(e){}
  if(!emp) return env.ASSETS.fetch(request); // no es empresa: página normal (bases, fechas con código, etc.)
  const c=String(emp.codigo).toLowerCase(), base=new URL(request.url).origin;
  // Tarjeta linda si ya está generada para este código; si no, el logo de la empresa
  let img=emp.logo||base+"/icons/icon-512.png", grande=false;
  try{const a=await env.ASSETS.fetch(new Request(base+"/og/"+c+".jpg"));if(a.ok&&(a.headers.get("content-type")||"").includes("image")){img=base+"/og/"+c+".jpg?v="+encodeURIComponent((emp.nombre||"")+(emp.logo||"").slice(-12));grande=true;}}catch(e){}
  const t=esc(emp.nombre);
  const html=`<!doctype html><html lang="es"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>${t}</title>
<meta property="og:type" content="website"/><meta property="og:site_name" content="Polla Prodes"/>
<meta property="og:title" content="${t}"/><meta property="og:url" content="${base}/${c}"/>
<meta property="og:image" content="${esc(img)}"/>${grande?'<meta property="og:image:width" content="1200"/><meta property="og:image:height" content="630"/><meta name="twitter:card" content="summary_large_image"/>':""}
<script>location.replace("/?e="+encodeURIComponent("${c}"));</script>
</head><body style="background:#05070C"></body></html>`;
  return new Response(html,{headers:{"content-type":"text/html; charset=utf-8","cache-control":"no-store"}});
}
