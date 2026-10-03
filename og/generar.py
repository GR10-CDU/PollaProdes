# Vista previa (WhatsApp/redes) de cada empresa: og/<codigo>.jpg + <codigo>/index.html
# Corre solo en GitHub cada 30 min (.github/workflows/og.yml). Solo rehace las empresas que cambiaron.
# Local: set -a; source ../.secretos.env; set +a; python3 og/generar.py   (desde repo-pollaprodes)
import json,os,urllib.request,subprocess,html,pathlib,tempfile,time,hashlib
R=pathlib.Path(__file__).resolve().parent.parent; (R/"og").mkdir(exist_ok=True)
SITE="https://pollaprodes.ar/"
API="https://vznmqqdxfgqcnncbazvx.supabase.co/functions/v1/api"
CHROME=os.environ.get("CHROME_BIN","/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
FONT='<link href="https://fonts.googleapis.com/css2?family=Barlow+Condensed:wght@700;800&family=Plus+Jakarta+Sans:wght@500;700&display=swap" rel="stylesheet">'
PITCH='<svg style="position:absolute;inset:0;opacity:.07" viewBox="0 0 1200 630" fill="none" stroke="#fff" stroke-width="3"><rect x="40" y="40" width="1120" height="550" rx="8"/><line x1="600" y1="40" x2="600" y2="590"/><circle cx="600" cy="315" r="95"/><rect x="40" y="185" width="140" height="260"/><rect x="1020" y="185" width="140" height="260"/></svg>'
def tarjeta(logo,titulo,sub,pie,c1,c2,acento):
  return f'''<!doctype html><html><head><meta charset="utf-8">{FONT}<style>
  *{{margin:0;box-sizing:border-box}}body{{width:1200px;height:630px;overflow:hidden;font-family:'Plus Jakarta Sans',sans-serif;color:#fff;
  background:radial-gradient(70% 80% at 20% 0%,{acento}55,transparent 60%),linear-gradient(135deg,{c1},{c2});position:relative;display:flex;align-items:center;gap:56px;padding:0 80px}}
  .logo{{flex:none;width:300px;height:300px;border-radius:56px;background:#fff;display:grid;place-items:center;box-shadow:0 30px 70px rgba(0,0,0,.45);overflow:hidden}}
  .logo img{{width:86%;height:86%;object-fit:contain}}
  h1{{font-family:'Barlow Condensed';font-weight:800;font-size:96px;line-height:.9;text-transform:uppercase;letter-spacing:.01em}}
  p{{margin-top:22px;font-size:34px;font-weight:700;color:{acento}}}
  small{{display:block;margin-top:26px;font-size:24px;font-weight:500;opacity:.7}}
  </style></head><body>{PITCH}<div class="logo"><img src="{logo}"></div><div><h1>{titulo}</h1><p>{sub}</p><small>{pie}</small></div></body></html>'''
def captura(htmltxt,salida):
  # Chrome headless no siempre se cierra solo: se espera la imagen y se lo corta
  with tempfile.TemporaryDirectory() as d:
    f=pathlib.Path(d)/"og.html";f.write_text(htmltxt);png=pathlib.Path(d)/"og.png"
    pr=subprocess.Popen([CHROME,"--headless=new","--disable-gpu","--no-sandbox","--hide-scrollbars","--no-first-run",f"--user-data-dir={d}/p","--window-size=1200,630","--virtual-time-budget=6000",f"--screenshot={png}",f.as_uri()],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    for _ in range(120):
      time.sleep(0.5)
      if png.exists() and png.stat().st_size>0: time.sleep(0.5);break
    pr.kill()
    if not png.exists(): raise SystemExit("No se pudo generar la imagen")
    try:
      from PIL import Image
      Image.open(png).convert("RGB").save(salida,"JPEG",quality=86,optimize=True)
    except ImportError:
      subprocess.run(["sips","-s","format","jpeg","-s","formatOptions","86",str(png),"--out",str(salida)],capture_output=True)
def metas(titulo,desc,img,url):
  t,d=html.escape(titulo),html.escape(desc)
  return f'''<meta property="og:type" content="website"/>
<meta property="og:site_name" content="Polla Prodes"/>
<meta property="og:title" content="{t}"/>
<meta property="og:description" content="{d}"/>
<meta property="og:url" content="{url}"/>
<meta property="og:image" content="{img}"/>
<meta property="og:image:width" content="1200"/>
<meta property="og:image:height" content="630"/>
<meta name="twitter:card" content="summary_large_image"/>
<meta name="description" content="{d}"/>'''

def empresas():
  body=json.dumps({"action":"ogEmpresas","apiSecret":os.environ["API_SECRET"],"ogSecret":os.environ["OG_SECRET"]}).encode()
  req=urllib.request.Request(API,data=body,headers={"Authorization":"Bearer "+os.environ["ANON_KEY"],"Content-Type":"application/json"})
  r=json.loads(urllib.request.urlopen(req,timeout=30).read())
  if not r.get("ok"): raise SystemExit("API: "+str(r.get("error")))
  return r["empresas"]
est_f=R/"og/estado.json"
try: estado=json.loads(est_f.read_text())
except Exception: estado={}
icon=(R/"icons/icon-512.png").resolve().as_uri()
cambios=0
for e in empresas():
  cod=e["codigo"].lower()
  h=hashlib.sha1(json.dumps(e,sort_keys=True).encode()).hexdigest()[:12]
  if estado.get(cod)==h and (R/f"og/{cod}.jpg").exists() and (R/cod/"index.html").exists(): continue
  c=e["color"] or "#2F5BEA"
  captura(tarjeta(e["logo"] or icon,html.escape(e["nombre"]),html.escape(e["slogan"] or "La Polla de "+e["nombre"]),"Jugá gratis con tu código · con Polla Prodes",c,"#05070C","#FFFFFF"),R/f"og/{cod}.jpg")
  m=metas(f"Polla {e['nombre']}",(e["slogan"] or f"El prode de {e['nombre']}")+". Entrá, pronosticá y competí con tu gente.",SITE+f"og/{cod}.jpg?v={h}",SITE+cod)
  (R/cod).mkdir(exist_ok=True)
  (R/cod/"index.html").write_text(f"""<!doctype html><html lang="es"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Polla {html.escape(e["nombre"])}</title>
{m}
<script>location.replace("../?e="+encodeURIComponent("{cod}"));</script>
</head><body style="background:#05070C"></body></html>""")
  estado[cod]=h;cambios+=1;print("actualizada:",e["nombre"],"→",cod)
est_f.write_text(json.dumps(estado,indent=1,sort_keys=True))
print("empresas actualizadas:",cambios)
