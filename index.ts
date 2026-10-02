// ============================================================
//  POLLA PRODES — Edge Function principal
//  Supabase Edge Functions (Deno)
//  2026-04-06 21:30 ARG — Fixes: nombres equipos, tabla, pozo actual
// ============================================================

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SUPABASE_SERVICE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const API_SECRET = Deno.env.get("API_SECRET")!;

const REGLAS_DEF: Record<string, any> = {
  LMR:  { nombre:"La Marea Roja",    pts:1,  cantPartidos:3, desc:"Elegí 3 partidos con tarjeta roja. +1pt por expulsión." },
  LR:   { nombre:"La Rachita",       pts:4,  cantPartidos:1, desc:"Elegí un partido inicio. 1pt si acertás el 1ro, 2pts el 2do, 4pts el 3ro." },
  LLDG: { nombre:"Lluvia de Goles",  pts:4,  cantPartidos:1, desc:"5+ goles → 4pts." },
  DIEGO:{ nombre:"El Diego",         pts:5,  cantPartidos:3, desc:"3 empates acertados → 5pts." },
  GSA:  { nombre:"Goles Son Amores", pts:1,  cantPartidos:1, desc:"Ambos anotan → 1pt/gol." },
  ZPL:  { nombre:"La Zapali",        pts:4,  cantPartidos:1, desc:"Diferencia 3+ goles → 4pts." },
  MK:   { nombre:"La MK",            pts:5,  cantPartidos:1, desc:"Resultado exacto → 5pts." },
  EQS:  { nombre:"Empate Que Suma",  pts:3,  cantPartidos:1, desc:"Empate → 3pts." },
};

const PTS_NORMAL = 1, PTS_DOBLE = 2, PTS_POLLA = 5, TOLE_UMBRAL = 45, TOLE_PTS = 3;
const MAX_CAMBIOS = 3, MINUTOS_CIERRE = 30, MINUTOS_CIERRE_CAMBIO = 60;
// CIERRE DE LA FECHA = 1 hora antes del primer partido (o el plazo que cargó el admin, si es antes).
// Hasta el cierre: inscripción, pronósticos nuevos, cambios gratis y reglas. Después: solo cambios pagos,
// cada uno hasta 1 hora antes de su propio partido.
function cierreFecha(fecha: any, parts: any[]): Date | null {
  const t = (parts||[]).map((p:any) => p.fecha_hora ? new Date(p.fecha_hora).getTime() : NaN).filter((x:number) => !isNaN(x));
  const porPartido = t.length ? Math.min(...t) - MINUTOS_CIERRE_CAMBIO*60000 : NaN;
  const porAdmin = fecha?.plazo_limite ? new Date(fecha.plazo_limite).getTime() : NaN;
  const v = [porPartido, porAdmin].filter(x => !isNaN(x));
  return v.length ? new Date(Math.min(...v)) : null;
}
const minutosHasta = (d: Date | null) => d ? Math.floor((d.getTime() - Date.now()) / 60000) : 99999;

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Content-Type": "application/json",
  };
}

function resp(data: any, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: corsHeaders() });
}

function hashPin(pin: string): string {
  const encoder = new TextEncoder();
  const data = encoder.encode(pin + "PP2026SALT");
  return crypto.subtle.digest("SHA-256", data).then(buf =>
    Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,"0")).join("")
  ) as any;
}

async function hashPinAsync(pin: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(pin + "PP2026SALT");
  const buf = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,"0")).join("");
}

// PIN: PBKDF2-SHA256 con sal propia por usuario. Formato guardado: "pbkdf2$<iteraciones>$<sal hex>$<hash hex>".
// Los hashes viejos (SHA-256 con sal fija) se aceptan una vez y se actualizan solos al entrar.
const PBKDF2_ITER = 100000;
const toHex = (b: Uint8Array) => Array.from(b).map(x => x.toString(16).padStart(2,"0")).join("");
const fromHex = (h: string) => new Uint8Array(h.match(/../g)!.map(x => parseInt(x,16)));

async function pbkdf2(pin: string, salt: Uint8Array, iter: number): Promise<string> {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(pin), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({name:"PBKDF2", hash:"SHA-256", salt, iterations:iter}, key, 256);
  return toHex(new Uint8Array(bits));
}
async function hashPinSeguro(pin: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  return `pbkdf2$${PBKDF2_ITER}$${toHex(salt)}$${await pbkdf2(pin, salt, PBKDF2_ITER)}`;
}
function igualSeguro(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let r = 0; for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}
async function verificarPin(pin: string, guardado: string): Promise<{ok:boolean, viejo:boolean}> {
  if (guardado?.startsWith("pbkdf2$")) {
    const [, it, sal, h] = guardado.split("$");
    return {ok: igualSeguro(await pbkdf2(pin, fromHex(sal), parseInt(it)), h), viejo:false};
  }
  return {ok: igualSeguro(await hashPinAsync(pin), guardado || ""), viejo:true};
}
const PIN_OK = (pin: any) => /^\d{4,8}$/.test(String(pin||""));
const MAX_INTENTOS = 5, MINUTOS_BLOQUEO = 15;

// Mail (Resend). Si falta RESEND_API_KEY no se manda nada y el registro sigue igual.
async function enviarMail(para: string, asunto: string, html: string) {
  const KEY = Deno.env.get("RESEND_API_KEY");
  if (!KEY || !para) return {ok:false, motivo:"sin configurar"};
  try {
    const r = await fetch("https://api.resend.com/emails", {
      method:"POST",
      headers:{"Authorization":`Bearer ${KEY}`, "Content-Type":"application/json"},
      body: JSON.stringify({from: Deno.env.get("MAIL_FROM") || "Polla Prodes <hola@pollaprodes.ar>", to:[para], subject:asunto, html}),
    });
    return {ok:r.ok};
  } catch (e) { console.error("mail", e); return {ok:false}; }
}
const esc = (t: any) => String(t ?? "").replace(/[&<>"]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"} as any)[c]);
function mailBienvenida(nombre: string, usuario: string, tel: string, alias: string) {
  const APP_URL = Deno.env.get("APP_URL") || "https://gr10-cdu.github.io/PollaProdes/";
  return `<div style="font-family:Arial,sans-serif;max-width:520px;margin:auto;background:#0B2A1B;border-radius:18px;overflow:hidden;color:#fff">
  <div style="padding:28px 28px 8px"><div style="font-size:30px;font-weight:900;letter-spacing:2px">POLLA <span style="color:#3BEA8B">PRODES</span></div></div>
  <div style="padding:8px 28px 28px">
    <p style="font-size:18px">¡Hola ${esc(nombre)}! Ya sos parte de Polla Prodes.</p>
    <p style="color:#B8D8C6">Estos son los datos de tu registro:</p>
    <table style="width:100%;background:#06140D;border-radius:12px;padding:12px;color:#fff">
      <tr><td style="color:#8FB3A0;padding:6px">Usuario</td><td style="font-weight:bold;padding:6px">${esc(usuario)}</td></tr>
      <tr><td style="color:#8FB3A0;padding:6px">Teléfono</td><td style="font-weight:bold;padding:6px">${esc(tel)}</td></tr>
      ${alias ? `<tr><td style="color:#8FB3A0;padding:6px">Alias MP</td><td style="font-weight:bold;padding:6px">${esc(alias)}</td></tr>` : ""}
    </table>
    <p style="color:#B8D8C6;margin-top:16px">Para entrar usás tu teléfono y tu PIN. Nunca te vamos a pedir el PIN por mail ni por WhatsApp.</p>
    <a href="${APP_URL}" style="display:inline-block;margin-top:10px;background:#27E07F;color:#03140A;font-weight:bold;text-decoration:none;padding:14px 22px;border-radius:12px">Entrar a jugar →</a>
    <p style="color:#6E8F7E;font-size:12px;margin-top:22px">Si no te registraste vos, respondé este mail y lo revisamos.</p>
  </div></div>`;
}

function generarId(prefix: string): string {
  return prefix + "_" + Date.now().toString(36).toUpperCase() + Math.random().toString(36).substring(2,6).toUpperCase();
}

function generarUsuario(nombre: string, tel: string): string {
  const palabras = nombre.trim().toUpperCase().split(/\s+/);
  let letras = palabras.length >= 2 ? palabras[0][0] + palabras[1][0] : palabras[0].substring(0,2);
  letras = letras.replace(/[^A-Z]/g,"X").padEnd(2,"X").substring(0,2);
  const digitos = tel.replace(/\D/g,"").slice(-3);
  return letras + digitos;
}

async function requireAuth(db: any, data: any): Promise<{ok:boolean, userId?:string, rol?:string, empresaId?:string|null, error?:string}> {
  if (!data.sessionToken) return {ok:false, error:"Sin sesión"};
  const { data: sesion } = await db.from("sesiones")
    .select("user_id, expira")
    .eq("token", data.sessionToken)
    .single();
  if (!sesion) return {ok:false, error:"Sesión inválida"};
  if (new Date(sesion.expira) < new Date()) {
    await db.from("sesiones").delete().eq("token", data.sessionToken);
    return {ok:false, error:"Sesión expirada"};
  }
  const { data: user } = await db.from("usuarios").select("rol,empresa_id").eq("id", sesion.user_id).single();
  return {ok:true, userId: sesion.user_id, rol: user?.rol || "Jugador", empresaId: user?.empresa_id || null};
}

// ── ROUTER ──────────────────────────────────────────────────
Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, {headers: corsHeaders()});
  if (new URL(req.url).searchParams.get("webhook") === "mp") {
    try { await webhookMP(createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY), req); } catch (e) { console.error("webhook", e); }
    return new Response("ok", {status:200});
  }
  if (req.method !== "POST") return resp({ok:false, error:"Method not allowed"}, 405);

  let data: any;
  try { data = await req.json(); } catch { return resp({ok:false, error:"Invalid JSON"}, 400); }

  if (data.apiSecret !== API_SECRET) return resp({ok:false, error:"No autorizado"}, 401);

  const db = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);
  const { action } = data;

  try {
    switch(action) {

      // ── AUTH ──────────────────────────────────────────────
      case "registro": return resp(await registro(db, data));
      case "login": return resp(await login(db, data));
      case "loginConToken": return resp(await loginConToken(db, data));
      case "logout": return resp(await logout(db, data));

      // ── FECHAS Y PARTIDOS ─────────────────────────────────
      case "getFechas": return resp(await getFechas(db, data));
      // ── EMPRESAS ──────────────────────────────────────────
      case "getEmpresaPublica": return resp(await getEmpresaPublica(db, data));
      case "jugarEmpresa": return resp(await jugarEmpresa(db, data));
      case "getNovedades": return resp(await getNovedades(db, data));
      case "guardarNovedad": return resp(await guardarNovedad(db, data));
      case "borrarNovedad": return resp(await borrarNovedad(db, data));
      case "guardarMarcaEmpresa": return resp(await guardarMarcaEmpresa(db, data));
      case "adminGetEmpresas": return resp(await adminGetEmpresas(db, data));
      case "adminGuardarEmpresa": return resp(await adminGuardarEmpresa(db, data));
      case "adminSetRol": return resp(await adminSetRol(db, data));
      case "adminInvitarAdmin": return resp(await adminInvitarAdmin(db, data));
      case "adminQuitarInvitacion": return resp(await adminQuitarInvitacion(db, data));
      case "empresaGetEmpleados": return resp(await empresaGetEmpleados(db, data));
      case "guardarMisDatosEmpresa": return resp(await guardarMisDatosEmpresa(db, data));
      case "adminOcultarFecha": return resp(await adminOcultarFecha(db, data));
      case "adminEliminarFecha": return resp(await adminEliminarFecha(db, data));
      case "adminCopiarFecha": return resp(await adminCopiarFecha(db, data));
      case "getFecha": return resp(await getFecha(db, data));

      // ── POZOS E INSCRIPCIONES ─────────────────────────────
      case "getPozos": return resp(await getPozos(db, data));
      case "inscribirse": return resp(await inscribirse(db, data));
      case "getMisInscripciones": return resp(await getMisInscripciones(db, data));
      case "crearPreferencia": return resp(await crearPreferencia(db, data));
      case "verificarPagoInscripcion": return resp(await verificarPagoInscripcion(db, data));
      case "getDatosPago": return resp(await getDatosPago(db, data));
      case "enviarComprobanteInscripcion": return resp(await enviarComprobanteInscripcion(db, data));
      case "enviarComprobanteCambio": return resp(await enviarComprobanteCambio(db, data));
      case "adminGetPagos": return resp(await adminGetPagos(db, data));
      case "adminResolverPago": return resp(await adminResolverPago(db, data));
      case "adminGuardarDatosPago": return resp(await adminGuardarDatosPago(db, data));
      case "getAvisos": return resp(await getAvisos(db, data));

      // ── PRONÓSTICOS ───────────────────────────────────────
      case "autoguardar": return resp(await autoguardar(db, data));
      case "getMiFecha": return resp(await getMiFecha(db, data));
      case "guardarReglas": return resp(await guardarReglas(db, data));

      // ── CAMBIOS PAGOS ─────────────────────────────────────
      case "getMisCambios": return resp(await getMisCambios(db, data));
      case "solicitarCambio": return resp(await solicitarCambio(db, data));
      case "crearPreferenciaCambio": return resp(await crearPreferenciaCambio(db, data));
      case "ejecutarCambio": return resp(await ejecutarCambio(db, data));
      case "adminHabilitarCambio": return resp(await adminHabilitarCambio(db, data));
      case "pagarCambioPrueba": return resp(await pagarCambioPrueba(db, data));

      // ── PUNTAJES ──────────────────────────────────────────
      case "getTabla": return resp(await getTabla(db, data));
      case "getNoticias": return resp(await getNoticias(db));

      // ── ADMIN ─────────────────────────────────────────────
      case "adminCrearFecha": return resp(await adminCrearFecha(db, data));
      case "adminEditarFecha": return resp(await adminEditarFecha(db, data));
      case "adminCerrarFecha": return resp(await adminCerrarFecha(db, data));
      case "adminCrearPozo": return resp(await adminCrearPozo(db, data));
      case "adminIngresarResultado": return resp(await adminIngresarResultado(db, data));
      case "adminEstadoPartido": return resp(await adminEstadoPartido(db, data));
      case "adminGetUsuarios": return resp(await adminGetUsuarios(db, data));
      case "agregarNoticia": return resp(await agregarNoticia(db, data));
      case "eliminarNoticia": return resp(await eliminarNoticia(db, data));
      case "importarPartidos": return resp(await importarPartidos(db, data));
      case "adminAgregarPartido": return resp(await adminAgregarPartido(db, data));
      case "adminEditarPartido": return resp(await adminEditarPartido(db, data));
      case "adminBorrarPartido": return resp(await adminBorrarPartido(db, data));
      case "buscarEquipos": return resp(await buscarEquipos(db, data));
      case "getRondas": return resp(await getRondas(db, data));
      case "buscarPorRonda": return resp(await buscarPorRonda(db, data));

      // ── Acciones adicionales ──
      case "editarPerfil": return resp(await editarPerfil(db, data));
      case "getGrilla": return resp(await getGrilla(db, data));
      case "getEstadisticas": return resp(await getEstadisticas(db, data));
      case "adminCerrarYCalcular": return resp(await adminCerrarYCalcular(db, data));
      case "adminHabilitarManual": return resp(await adminHabilitarManual(db, data));
      case "adminCambiarEstado": return resp(await adminCambiarEstado(db, data));
      case "adminGetInscripcionesPendientes": return resp(await adminGetInscripcionesPendientes(db, data));
      case "getGrupoPorCodigo": return resp(await getGrupoPorCodigo(db, data));
      case "unirseConCodigo": return resp(await unirseConCodigo(db, data));
      case "subirFoto": return resp(await subirFoto(db, data));
      case "cancelarFoto": return resp(await cancelarFoto(db, data));
      case "adminGetFotosPendientes": return resp(await adminGetFotosPendientes(db, data));
      case "adminResolverFoto": return resp(await adminResolverFoto(db, data));

      default: return resp({ok:false, error:`Acción desconocida: ${action}`}, 404);
    }
  } catch(e: any) {
    console.error("Error en", action, e.message);
    return resp({ok:false, error:"Error interno: " + e.message}, 500);
  }
});

// ============================================================
//  REGISTRO
// ============================================================
async function registro(db: any, data: any) {
  const { nombre, telefono, pin } = data;
  if (!nombre || !telefono || !pin) return {ok:false, error:"Faltan datos"};
  const tel = telefono.replace(/\D/g,"");
  if (String(nombre).trim().length < 3) return {ok:false, error:"Escribí tu nombre y apellido"};
  if (tel.length < 8 || tel.length > 15) return {ok:false, error:"El teléfono no parece válido"};
  if (!PIN_OK(pin)) return {ok:false, error:"El PIN tiene que tener entre 4 y 8 números"};
  if (data.pin2 !== undefined && data.pin2 !== pin) return {ok:false, error:"Los PIN no coinciden"};
  if (data.email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(data.email)) return {ok:false, error:"El email no parece válido"};
  const pinHash = await hashPinSeguro(pin);

  // Verificar si existe
  const {data: existe} = await db.from("usuarios").select("id").eq("telefono", tel).single();
  if (existe) return {ok:false, error:"Teléfono ya registrado"};

  // Código de empresa (opcional): la cuenta queda atada a esa empresa
  let empresa: any = null;
  if (data.codigoEmpresa) {
    empresa = await empresaPorCodigo(db, data.codigoEmpresa);
    if (!empresa) return {ok:false, error:"El código de empresa no existe"};
  }
  // ¿Lo invitaron por correo como admin de una empresa?
  const email = String(data.email||"").trim().toLowerCase();
  let invitacion: any = null;
  if (email) {
    const {data: inv} = await db.from("empresa_invitaciones").select("*").ilike("email", email);
    invitacion = (inv||[]).find((i:any) => !empresa || i.empresa_id === empresa.id) || null;
    if (invitacion && !empresa) { const {data: e} = await db.from("empresas").select("*").eq("id", invitacion.empresa_id).maybeSingle(); empresa = e; }
  }
  let datosExtra: any = {};
  if (empresa) {
    const v = validarDatosEmpresa(empresa, data.datosExtra || {});
    if (v.error) return {ok:false, error:v.error};
    datosExtra = v.datos;
  }

  const usuario = generarUsuario(nombre, tel);
  const id = generarId("USR");

  const {error} = await db.from("usuarios").insert({
    id, telefono: tel, pin_hash: pinHash, usuario, nombre,
    alias_mp: empresa ? "" : (data.alias || ""), email: email || "", empresa_id: empresa?.id || null,
    datos_extra: datosExtra, rol: invitacion ? "AdminEmpresa" : "Jugador",
  });
  if (error) return {ok:false, error: error.message};

  const token = await crearSesion(db, id);
  if (data.email) await enviarMail(data.email, "¡Bienvenido a Polla Prodes!", mailBienvenida(nombre, usuario, tel, data.alias || ""));
  if (invitacion) await db.from("empresa_invitaciones").delete().eq("id", invitacion.id);
  return {ok:true, user:{id, usuario, nombre, rol: invitacion ? "AdminEmpresa" : "Jugador", empresa: empresaOut(empresa), datosExtra}, sessionToken: token};
}

// ============================================================
//  LOGIN
// ============================================================
async function login(db: any, data: any) {
  const tel = data.telefono?.replace(/\D/g,"");
  if (!tel || !data.pin) return {ok:false, error:"Faltan datos"};

  const {data: user} = await db.from("usuarios")
    .select("*").eq("telefono", tel).single();
  if (!user) return {ok:false, error:"Teléfono no registrado"};
  if (user.estado !== "Activo") return {ok:false, error:"Cuenta suspendida"};
  if (user.bloqueado_hasta && new Date(user.bloqueado_hasta) > new Date()) {
    const min = Math.ceil((new Date(user.bloqueado_hasta).getTime() - Date.now()) / 60000);
    return {ok:false, error:`Demasiados intentos. Probá de nuevo en ${min} minuto${min!==1?"s":""}`};
  }

  const v = await verificarPin(String(data.pin), user.pin_hash);
  if (!v.ok) {
    const n = (user.intentos_fallidos || 0) + 1;
    const bloquear = n >= MAX_INTENTOS;
    await db.from("usuarios").update({
      intentos_fallidos: bloquear ? 0 : n,
      bloqueado_hasta: bloquear ? new Date(Date.now() + MINUTOS_BLOQUEO*60000).toISOString() : null,
    }).eq("id", user.id);
    if (bloquear) return {ok:false, error:`Demasiados intentos. Tu cuenta quedó trabada ${MINUTOS_BLOQUEO} minutos`};
    const quedan = MAX_INTENTOS - n;
    return {ok:false, error:`PIN incorrecto. Te quedan ${quedan} intento${quedan!==1?"s":""}`};
  }

  const upd: any = {ultimo_login: new Date().toISOString(), intentos_fallidos: 0, bloqueado_hasta: null};
  if (v.viejo) upd.pin_hash = await hashPinSeguro(String(data.pin)); // actualizar al formato seguro
  await db.from("usuarios").update(upd).eq("id", user.id);
  const token = await crearSesion(db, user.id);
  return {ok:true, user: await userOut(db, user), sessionToken: token};
}

// ============================================================
//  LOGIN CON TOKEN
// ============================================================
async function loginConToken(db: any, data: any) {
  const auth = await requireAuth(db, data);
  if (!auth.ok) return auth;
  const {data: user} = await db.from("usuarios").select("*").eq("id", auth.userId).single();
  if (!user) return {ok:false, error:"Usuario no encontrado"};
  return {ok:true, user: await userOut(db, user), sessionToken: data.sessionToken};
}

async function logout(db: any, data: any) {
  if (data.sessionToken) await db.from("sesiones").delete().eq("token", data.sessionToken);
  return {ok:true};
}

async function crearSesion(db: any, userId: string): Promise<string> {
  const token = crypto.randomUUID();
  const expira = new Date(Date.now() + 30*24*3600*1000).toISOString();
  await db.from("sesiones").insert({token, user_id: userId, expira});
  // Limpiar sesiones viejas
  await db.from("sesiones").delete().lt("expira", new Date().toISOString());
  return token;
}

// ============================================================
//  GET FECHAS
// ============================================================
async function getFechas(db: any, data: any) {
  const quien: any = data.sessionToken ? await requireAuth(db, data) : {ok:false};
  const esAdmin = quien.ok && quien.rol === "Admin";
  let q = db.from("fechas").select("*").in("estado", ["Abierta","Cerrada","Jugada"]).order("plazo_limite");
  if (!esAdmin) q = quien.ok && quien.empresaId ? q.eq("empresa_id", quien.empresaId) : q.is("empresa_id", null);
  const {data: fechas} = await q;
  const {data: emps} = esAdmin ? await db.from("empresas").select("id,nombre") : {data: []};

  const ids = (fechas||[]).map((f:any) => f.id);
  const {data: pts} = ids.length ? await db.from("partidos").select("fecha_id,fecha_hora").in("fecha_id", ids) : {data: []};
  return {ok:true, fechas: (fechas||[]).map((f:any) => {
    const cierre = cierreFecha(f, (pts||[]).filter((p:any) => p.fecha_id === f.id));
    const mins = minutosHasta(cierre);
    return {
      id: f.id, nombre: f.nombre, descripcion: f.descripcion,
      plazoLimite: cierre?.toISOString() || f.plazo_limite, estado: f.estado,
      cantPartidos: f.cant_partidos, liga: f.liga,
      reglasHabilitadas: f.reglas_habilitadas || [],
      puedeJugar: f.estado === "Abierta" && mins > 0,
      minutosRestantes: mins,
      tieneCodigo: !!f.codigo_grupo,
      empresaId: f.empresa_id || null, oculta: esAdmin ? !!f.oculta : undefined, cambiosGratis: !!(f.cambios_gratis || f.empresa_id),
      empresaNombre: esAdmin && f.empresa_id ? ((emps||[]).find((e:any) => e.id === f.empresa_id)?.nombre || "") : undefined,
      codigoGrupo: esAdmin ? (f.codigo_grupo || "") : undefined,
      pagoAlias: esAdmin ? (f.pago_alias || "") : undefined, pagoTitular: esAdmin ? (f.pago_titular || "") : undefined,
    };
  })};
}

// ============================================================
//  GET FECHA (con partidos)
// ============================================================
async function getFecha(db: any, data: any) {
  if (!data.fechaId) return {ok:false, error:"Falta fechaId"};

  const [{data: fecha}, {data: parts}] = await Promise.all([
    db.from("fechas").select("*").eq("id", data.fechaId).single(),
    db.from("partidos").select("*").eq("fecha_id", data.fechaId).order("numero"),
  ]);
  if (!fecha) return {ok:false, error:"Fecha no encontrada"};

  const ahora = new Date();
  const cierre = cierreFecha(fecha, parts||[]);
  const mins = minutosHasta(cierre);
  const reglasDetalle = (fecha.reglas_habilitadas||[]).filter((c:string) => REGLAS_DEF[c]).map((c:string) => ({
    codigo:c, ...REGLAS_DEF[c]
  }));

  return {ok:true,
    fecha: {id:fecha.id, nombre:fecha.nombre, descripcion:fecha.descripcion, plazoLimite:cierre?.toISOString()||fecha.plazo_limite, estado:fecha.estado, cantPartidos:fecha.cant_partidos, liga:fecha.liga, puedeJugar:fecha.estado==="Abierta"&&mins>0, minutosRestantes:mins, reglasHabilitadas:fecha.reglas_habilitadas||[], reglasDetalle, tieneCodigo:!!fecha.codigo_grupo, cambiosGratis:!!(fecha.cambios_gratis||fecha.empresa_id)},
    partidos: (parts||[]).map((p:any) => ({
      id:p.id, numero:p.numero, local:p.local, visita:p.visita,
      fechaHora:p.fecha_hora, liga:p.liga, tipo:p.tipo, estado:p.estado,
      golesLocal:p.goles_local, golesVisita:p.goles_visita,
      resultado:p.resultado, tarjetasRojas:p.tarjetas_rojas||0, esToleTole:!!p.es_tole,
      localLogo:p.local_logo||"", visitaLogo:p.visita_logo||"",
    })),
  };
}

// ============================================================
//  GET POZOS
// ============================================================
// Premio = 75% de (inscriptos que PAGARON × monto + cambios pagados). Si el pozo tiene premio fijo, es ese.
const COMISION_PCT = 25;
function calcPremio(pozo: any, inscAprobadas: any[], cambios: any[]) {
  const pagaron = inscAprobadas.filter((i:any) => i.pozo_id === pozo.id && !i.via_codigo).length;
  const totalCambios = cambios.filter((c:any) => c.pozo_id === pozo.id).reduce((t:number,c:any) => t+(c.monto||0), 0);
  const totalRecaudado = pagaron * pozo.monto + totalCambios;
  const premio = pozo.premio_fijo != null ? Number(pozo.premio_fijo) : Math.floor(totalRecaudado * (1 - COMISION_PCT/100));
  return {totalRecaudado, totalCambios, premio};
}

async function getPozos(db: any, data: any) {
  if (!data.fechaId) return {ok:false, error:"Falta fechaId"};

  const [{data: pozos}, {data: inscripciones}, {data: cambiosPagados}] = await Promise.all([
    db.from("pozos").select("*").eq("fecha_id", data.fechaId).eq("estado","Activo").order("monto"),
    db.from("inscripciones").select("*").eq("fecha_id", data.fechaId).in("estado_pago",["Pendiente","Aprobado"]),
    db.from("cambios_pagos").select("pozo_id,monto,estado").eq("fecha_id", data.fechaId).in("estado",["Pagado","Usado"]),
  ]);

  const {data: parts} = await db.from("partidos").select("id").eq("fecha_id", data.fechaId);
  const cantPartidos = parts?.length || 0;
  const {data: misRechazos} = data.userId ? await db.from("inscripciones").select("pozo_id,rechazo_motivo").eq("fecha_id",data.fechaId).eq("user_id",data.userId).eq("estado_pago","Rechazado") : {data: []};

  return {ok:true, pozos: (pozos||[]).map((p:any) => {
    const insc = (inscripciones||[]).filter((i:any) => i.pozo_id === p.id && i.estado_pago === "Aprobado");
    const cantInscriptos = insc.length;
    const {totalRecaudado, totalCambios, premio} = calcPremio(p, insc, cambiosPagados||[]);

    let yaInscripto = false, yaJugo = false, cambiosRestantesFecha = null, enRevision = false, rechazo = null;
    if (data.userId) {
      const miInsc = insc.find((i:any) => i.user_id === data.userId);
      yaInscripto = !!miInsc;
      const pend = (inscripciones||[]).find((i:any) => i.pozo_id === p.id && i.user_id === data.userId && i.estado_pago === "Pendiente");
      enRevision = !!(pend && pend.comprobante_path);
      if (enRevision) yaInscripto = true;
      const rech = (misRechazos||[]).find((i:any) => i.pozo_id === p.id);
      if (!yaInscripto && !enRevision && rech) rechazo = rech.rechazo_motivo || "Comprobante rechazado";
      
      // Calcular cambios restantes del usuario
      if (yaInscripto) {
        // Necesitamos contar cambios realizados del usuario
        // Por ahora dejamos null, el frontend lo calcula con getMiFecha
      }
    }

    return {
      id:p.id, fechaId:p.fecha_id, nombre:p.nombre, monto:p.monto,
      tipo:p.tipo, estado:p.estado, comisionPct:COMISION_PCT, premioFijo:p.premio_fijo,
      inscriptos:cantInscriptos, 
      totalRecaudado,
      totalCambios,
      premioGanador:premio,
      pozoActual: premio, // Alias más claro
      cantPartidos, yaInscripto, yaJugo, cambiosRestantesFecha, enRevision, rechazo,
    };
  })};
}

// ============================================================
//  INSCRIBIRSE
// ============================================================
async function inscribirse(db: any, data: any) {
  const auth = await requireAuth(db, data);
  if (!auth.ok) return auth;

  const {fechaId, pozoId} = data;
  if (!fechaId || !pozoId) return {ok:false, error:"Faltan datos"};

  // Verificar fecha abierta
  const {data: fecha} = await db.from("fechas").select("*").eq("id", fechaId).single();
  if (!fecha || fecha.estado !== "Abierta") return {ok:false, error:"Fecha cerrada"};
  if ((fecha.empresa_id || null) !== (auth.empresaId || null)) return {ok:false, error:"Esta fecha no es de tu grupo"};
  if (fecha.codigo_grupo) return {ok:false, error:"Esta fecha es con código: ingresalo para jugar", pideCodigo:true};
  const {data: partsF} = await db.from("partidos").select("fecha_hora").eq("fecha_id", fechaId);
  if (minutosHasta(cierreFecha(fecha, partsF||[])) <= 0) return {ok:false, error:"La fecha ya cerró (1 hora antes del primer partido)"};

  // Verificar si ya está inscripto
  const {data: yaInsc} = await db.from("inscripciones")
    .select("*").eq("user_id", auth.userId).eq("pozo_id", pozoId)
    .in("estado_pago",["Pendiente","Aprobado"]).single();

  if (yaInsc?.estado_pago === "Aprobado") return {ok:true, inscripcionId:yaInsc.id, habilitado:true};
  if (yaInsc?.estado_pago === "Pendiente") return {ok:true, inscripcionId:yaInsc.id, habilitado:false};

  const {data: user} = await db.from("usuarios").select("usuario").eq("id", auth.userId).single();
  const {data: pozo} = await db.from("pozos").select("monto,fecha_id").eq("id", pozoId).single();
  if (!pozo || pozo.fecha_id !== fechaId) return {ok:false, error:"Pozo inválido"};
  const gratis = !Number(pozo.monto);
  const id = generarId("INS");
  await db.from("inscripciones").insert({
    id, user_id:auth.userId, usuario:user?.usuario, fecha_id:fechaId, pozo_id:pozoId,
    estado_pago: gratis ? "Aprobado" : "Pendiente", habilitado: gratis, via_codigo: gratis,
    pagado_at: gratis ? new Date().toISOString() : null,
  });

  return {ok:true, inscripcionId:id, habilitado:gratis};
}

// ============================================================
//  GET MIS INSCRIPCIONES
// ============================================================
async function getMisInscripciones(db: any, data: any) {
  const auth = await requireAuth(db, data);
  if (!auth.ok) return auth;

  const {data: insc} = await db.from("inscripciones")
    .select("*, pozos(monto)")
    .eq("user_id", auth.userId).or("estado_pago.eq.Aprobado,and(estado_pago.eq.Pendiente,comprobante_path.not.is.null)");

  return {ok:true, inscripciones:(insc||[]).map((i:any) => ({
    inscripcionId:i.id, fechaId:i.fecha_id, pozoId:i.pozo_id, monto:i.pozos?.monto||0,
  }))};
}

// ============================================================
//  CREAR PREFERENCIA MP
// ============================================================
async function crearPreferencia(db: any, data: any) {
  const auth = await requireAuth(db, data);
  if (!auth.ok) return auth;

  const MP_TOKEN = Deno.env.get("MP_ACCESS_TOKEN");
  if (!MP_TOKEN) return {ok:false, error:"MercadoPago no configurado"};

  const {data: insc} = await db.from("inscripciones")
    .select("*, fechas(nombre), pozos(nombre,monto)")
    .eq("id", data.inscripcionId).eq("user_id", auth.userId).single();
  if (!insc) return {ok:false, error:"Inscripción no encontrada"};
  if (insc.estado_pago === "Aprobado") return {ok:false, error:"Ya pagado"};

  const titulo = `Polla Prodes — ${insc.fechas?.nombre} — ${insc.pozos?.nombre}`;
  const monto = insc.pozos?.monto || 0;
  const APP_URL = Deno.env.get("APP_URL") || "https://gr10-cdu.github.io/PollaProdes/";

  const mpResp = await fetch("https://api.mercadopago.com/checkout/preferences", {
    method:"POST",
    headers:{"Content-Type":"application/json","Authorization":`Bearer ${MP_TOKEN}`},
    body:JSON.stringify({
      items:[{title:titulo, quantity:1, unit_price:monto, currency_id:"ARS"}],
      back_urls:{success:`${APP_URL}?pago=ok&insc=${data.inscripcionId}`,failure:`${APP_URL}?pago=error`,pending:`${APP_URL}?pago=pendiente`},
      auto_return:"approved",
      external_reference:data.inscripcionId,
      notification_url: `${SUPABASE_URL}/functions/v1/api?webhook=mp`,
    }),
  });
  const mpData = await mpResp.json();
  if (!mpData.id) return {ok:false, error:"Error MP"};

  return {ok:true, preferenceId:mpData.id, initPoint:mpData.init_point, sandboxUrl:mpData.sandbox_init_point};
}

// ============================================================
//  AUTOGUARDAR PRONÓSTICOS (batch)
// ============================================================
async function autoguardar(db: any, data: any) {
  const auth = await requireAuth(db, data);
  if (!auth.ok) return auth;

  const {fechaId, pozoId, pronos} = data;
  if (!pronos?.length) return {ok:true, guardados:0};

  // Verificar habilitación
  const {data: insc} = await db.from("inscripciones")
    .select("id").eq("user_id",auth.userId).eq("fecha_id",fechaId).eq("pozo_id",pozoId).or("estado_pago.eq.Aprobado,and(estado_pago.eq.Pendiente,comprobante_path.not.is.null)").limit(1).maybeSingle();
  if (!insc) return {ok:false, error:"No habilitado"};

  // Leer partidos y pronósticos existentes en paralelo
  const [{data:parts}, {data:existentes}] = await Promise.all([
    db.from("partidos").select("*").eq("fecha_id",fechaId),
    db.from("pronosticos").select("*").eq("user_id",auth.userId).eq("fecha_id",fechaId).eq("pozo_id",pozoId),
  ]);
  const {data: fechaRow} = await db.from("fechas").select("plazo_limite").eq("id",fechaId).single();
  const libre = minutosHasta(cierreFecha(fechaRow, parts||[])) > 0;
  if (!libre) return {ok:false, error:"La fecha ya cerró: solo podés hacer cambios pagos"};

  const {data: user} = await db.from("usuarios").select("usuario").eq("id",auth.userId).single();
  const ahora = new Date();
  const upserts: any[] = [];
  let cambiosUsados = (existentes||[]).reduce((t:number,p:any) => t+(p.cambios_realizados||0), 0);
  const cambiosRestantes = Math.max(0, MAX_CAMBIOS - cambiosUsados);
  let guardados = 0;

  for (const p of pronos) {
    if (!["L","E","V"].includes(p.pronostico)) continue;
    const part = parts?.find((pt:any) => pt.id === p.partidoId);
    if (!part) continue;
    const diffMin = part.fecha_hora ? (new Date(part.fecha_hora).getTime() - ahora.getTime()) / 60000 : 9999;
    if (part.estado === "Finalizado" || part.estado === "Suspendido") continue;
    if (part.fecha_hora && diffMin <= MINUTOS_CIERRE) continue;

    const existente = existentes?.find((e:any) => e.partido_id === p.partidoId);
    const esCambio = existente && existente.pronostico !== p.pronostico;
    // Antes del período libre los cambios son gratis; después se pagan (solicitarCambio → ejecutarCambio)
    if (esCambio && !libre) continue;

    upserts.push({
      id: existente?.id || generarId("PRO"),
      user_id: auth.userId, usuario: user?.usuario,
      fecha_id: fechaId, pozo_id: pozoId, partido_id: p.partidoId,
      numero_partido: part.numero, local: part.local, visita: part.visita,
      pronostico: p.pronostico, updated_at: new Date().toISOString(),
      cambios_realizados: existente ? (existente.cambios_realizados||0) : 0, // los cambios gratis no cuentan
    });
    guardados++;
  }

  if (upserts.length) {
    await db.from("pronosticos").upsert(upserts, {onConflict:"user_id,partido_id,pozo_id"});
  }

  return {ok:true, guardados, cambiosRestantesFecha:Math.max(0, MAX_CAMBIOS-cambiosUsados)};
}

// ============================================================
//  GET MI FECHA (pronósticos + puntajes)
// ============================================================
async function getMiFecha(db: any, data: any) {
  const auth = await requireAuth(db, data);
  if (!auth.ok) return auth;

  const {fechaId, pozoId} = data;
  const [
    {data:pronos}, {data:reglas}, {data:puntos}, {data:parts}, {data:cambios}
  ] = await Promise.all([
    db.from("pronosticos").select("*").eq("user_id",auth.userId).eq("fecha_id",fechaId).eq("pozo_id",pozoId),
    db.from("reglas").select("*").eq("user_id",auth.userId).eq("fecha_id",fechaId).eq("pozo_id",pozoId),
    db.from("puntajes").select("*").eq("user_id",auth.userId).eq("fecha_id",fechaId).eq("pozo_id",pozoId),
    db.from("partidos").select("*").eq("fecha_id",fechaId).order("numero"),
    db.from("cambios_pagos").select("*").eq("user_id",auth.userId).eq("fecha_id",fechaId).eq("pozo_id",pozoId),
  ]);

  const ahora = new Date();
  const {data: fechaMF} = await db.from("fechas").select("plazo_limite,empresa_id,cambios_gratis").eq("id",fechaId).single();
  const cambiosUsados = (pronos||[]).reduce((t:number,p:any) => t+(p.cambios_realizados||0), 0);
  const cambiosRestantes = Math.max(0, MAX_CAMBIOS - cambiosUsados);
  
  // Calcular costo del próximo cambio
  const COSTO_CAMBIO: Record<number, number> = {1: 20, 2: 25, 3: 30};
  const proximoCambio = cambiosUsados + 1;
  const proximoPorcentaje = COSTO_CAMBIO[proximoCambio] || 30;
  
  // Obtener monto del pozo para calcular costo
  const {data: pozo} = await db.from("pozos").select("monto").eq("id", pozoId).single();
  const montoPozo = pozo?.monto || 0;
  const cambiosGratis = !!(fechaMF?.empresa_id || fechaMF?.cambios_gratis || !Number(montoPozo));
  const proximoCosto = cambiosGratis ? 0 : Math.round(montoPozo * proximoPorcentaje / 100);

  // Cambios pendientes de ejecutar
  const cambiosEnRevision = (cambios||[]).filter((c:any) => c.mp_status === "revision").map((c:any) => ({id:c.id, partidoId:c.partido_id, de:c.pronostico_anterior, a:c.pronostico_nuevo, monto:c.monto}));
  const cambiosPendientes = (cambios||[]).filter((c:any) => c.estado === "Pagado").map((c:any) => {
    const part = parts?.find((p:any) => p.id === c.partido_id);
    return {
      id: c.id, partidoId: c.partido_id, 
      de: c.pronostico_anterior, a: c.pronostico_nuevo,
      estado: c.estado, local: part?.local, visita: part?.visita
    };
  });

  const resultado = (pronos||[]).map((pr:any) => {
    // IMPORTANTE: Obtener nombres desde la tabla partidos, no desde pronosticos
    const part = parts?.find((p:any) => p.id === pr.partido_id);
    const pts = puntos?.find((p:any) => p.partido_id === pr.partido_id);
    const reglasPartido = (reglas||[]).filter((r:any) => r.partido_id === pr.partido_id);
    const diffMin = part?.fecha_hora ? (new Date(part.fecha_hora).getTime() - ahora.getTime()) / 60000 : 9999;
    const cambioPend = cambiosPendientes.find((c:any) => c.partidoId === pr.partido_id);
    
    return {
      id:pr.id, partidoId:pr.partido_id, numero:part?.numero || pr.numero_partido,
      // Usar nombres desde partidos (part), no desde pronosticos (pr)
      local: part?.local || pr.local || "Local",
      visita: part?.visita || pr.visita || "Visitante",
      localLogo: part?.local_logo,
      visitaLogo: part?.visita_logo,
      fechaHora: part?.fecha_hora,
      pronostico:pr.pronostico,
      acertado:pr.acertado, cambiosRealizados:pr.cambios_realizados||0,
      puedeCambiar:diffMin>MINUTOS_CIERRE_CAMBIO,
      reglas:reglasPartido.map((r:any) => ({codigo:r.codigo,nombre:r.nombre,detalle:r.detalle,puntos:r.puntos_obtenidos||0})),
      ptsGrilla:pts?(pts.pts_normal+pts.pts_doble+pts.pts_polla):null,
      ptsToleTole:pts?pts.pts_tole:null,
      ptsReglas:pts?pts.pts_reglas:null,
      ptsTotal:pts?pts.pts_total:null,
      esToleTole:pts?pts.es_tole:null,
      calculado:!!pts,
      cambioPendiente: cambioPend || null,
    };
  });

  const reglasMap = (reglas||[]).map((r:any) => {
    const part = parts?.find((p:any) => p.id === r.partido_id);
    const diffMin = part?.fecha_hora ? (new Date(part.fecha_hora).getTime() - ahora.getTime()) / 60000 : 9999;
    return {partidoId:r.partido_id, codigo:r.codigo, nombre:r.nombre, detalle:r.detalle, puntos:r.puntos_obtenidos||0, esMovible:diffMin>MINUTOS_CIERRE};
  });

  return {
    ok:true, 
    pronos:resultado, 
    reglas:reglasMap, 
    totalPartidos:parts?.length||0, 
    totalCompletos:resultado.length, 
    cambiosUsados,
    cambiosRestantes,
    proximoCambio,
    proximoPorcentaje,
    proximoCosto,
    cambiosGratis,
    cambiosPendientes,
    cambiosEnRevision,
    cambiosLibresHasta: libreHasta(parts||[], fechaMF)?.toISOString() || null,
    enPeriodoLibre: enPeriodoLibre(parts||[], fechaMF),
    // Legacy field
    cambiosRestantesFecha: cambiosRestantes
  };
}

// ============================================================
//  GUARDAR REGLAS BATCH
// ============================================================
async function guardarReglas(db: any, data: any) {
  const auth = await requireAuth(db, data);
  if (!auth.ok) return auth;

  const {fechaId, pozoId, reglas} = data;
  if (!reglas?.length) return {ok:true, guardadas:0};

  const {data: insc} = await db.from("inscripciones")
    .select("id").eq("user_id",auth.userId).eq("fecha_id",fechaId).eq("pozo_id",pozoId).or("estado_pago.eq.Aprobado,and(estado_pago.eq.Pendiente,comprobante_path.not.is.null)").limit(1).maybeSingle();
  if (!insc) return {ok:false, error:"No habilitado"};

  const {data: user} = await db.from("usuarios").select("usuario").eq("id",auth.userId).single();
  const {data: parts} = await db.from("partidos").select("*").eq("fecha_id",fechaId);
  const ahora = new Date();
  const nuevas: any[] = [];
  const codigosNuevos = reglas.map((r:any) => r.codigo);

  // Hasta 1 h antes del primer partido las reglas se mueven libremente (se reemplazan);
  // después, lo guardado queda fijo para siempre y solo se pueden completar lugares vacíos.
  const {data: fechaGR} = await db.from("fechas").select("plazo_limite").eq("id",fechaId).single();
  if (!enPeriodoLibre(parts||[], fechaGR)) return {ok:false, error:"La fecha ya cerró: las reglas quedaron fijas"};
  {
    await db.from("reglas").delete()
      .eq("user_id",auth.userId).eq("fecha_id",fechaId).eq("pozo_id",pozoId)
      .in("codigo",codigosNuevos);
  }
  const {data: existentes} = await db.from("reglas").select("codigo,partido_id")
    .eq("user_id",auth.userId).eq("fecha_id",fechaId).eq("pozo_id",pozoId);
  let ignoradas = 0;

  for (const reg of reglas) {
    const def = REGLAS_DEF[reg.codigo];
    if (!def) continue;
    const previas = new Set((existentes||[]).filter((e:any) => e.codigo === reg.codigo).map((e:any) => e.partido_id));
    let lugares = Math.max(0, def.cantPartidos - previas.size);
    for (const pid of (reg.partidos||[])) {
      if (previas.has(pid)) continue;
      if (lugares <= 0) { ignoradas++; continue; }
      const part = parts?.find((p:any) => p.id===pid);
      if (!part) continue;
      const diffMin = part.fecha_hora ? (new Date(part.fecha_hora).getTime()-ahora.getTime())/60000 : 9999;
      if (part.estado === "Finalizado" || part.estado === "Suspendido") continue;
      if (part.fecha_hora && diffMin <= MINUTOS_CIERRE) continue;
      nuevas.push({
        id:generarId("REG"), user_id:auth.userId, usuario:user?.usuario,
        fecha_id:fechaId, pozo_id:pozoId, partido_id:pid,
        numero_partido:part.numero, local:part.local, visita:part.visita,
        codigo:reg.codigo, nombre:def.nombre,
        detalle:reg.detalle||"", puntos_obtenidos:0,
      });
      lugares--;
    }
  }

  if (nuevas.length) await db.from("reglas").insert(nuevas);
  return {ok:true, guardadas:nuevas.length, ignoradas};
}

// ============================================================
//  GET TABLA
// ============================================================
async function armarTabla(db: any, fechaId: string, pozoId: string) {
  const [{data: pts}, {data: parts}, {data: usuarios}] = await Promise.all([
    db.from("puntajes").select("user_id,usuario,pts_normal,pts_doble,pts_polla,pts_tole,pts_reglas,pts_total,acertado,resultado_real,partido_id")
      .eq("fecha_id",fechaId).eq("pozo_id",pozoId),
    db.from("partidos").select("id,numero,estado").eq("fecha_id",fechaId).order("numero"),
    db.from("usuarios").select("id,nombre,usuario,avatar"),
  ]);
  const um: Record<string,any> = {};
  for (const u of (usuarios||[])) um[u.id] = u;
  const t: Record<string,any> = {};
  for (const p of (pts||[])) {
    const u = t[p.user_id] ||= {userId:p.user_id, siglas:p.usuario||um[p.user_id]?.usuario||"???", nombre:um[p.user_id]?.nombre||p.usuario||"Jugador", avatar:um[p.user_id]?.avatar||null,
      ptsTotal:0, ptsPartidos:0, ptsReglas:0, acertados:0, empatesAcertados:0, visitantesAcertados:0};
    u.ptsPartidos += (p.pts_normal||0)+(p.pts_doble||0)+(p.pts_polla||0)+(p.pts_tole||0);
    u.ptsReglas += p.pts_reglas||0;
    u.ptsTotal += p.pts_total||0;
    if (p.acertado) { u.acertados++; if (p.resultado_real==="E") u.empatesAcertados++; if (p.resultado_real==="V") u.visitantesAcertados++; }
  }
  const cmp = (a:any,b:any) => b.ptsTotal-a.ptsTotal || b.acertados-a.acertados || b.empatesAcertados-a.empatesAcertados || b.visitantesAcertados-a.visitantesAcertados;
  const lista = Object.values(t).sort(cmp);
  // Misma posición para los que empatan en todos los criterios
  lista.forEach((u:any,i:number) => { u.posicion = i>0 && cmp(lista[i-1],u)===0 ? lista[i-1].posicion : i+1; });
  const finalizados = (parts||[]).filter((p:any) => p.estado === "Finalizado");
  return {tabla:lista, ultimoPartidoCalculado: finalizados.length ? Math.max(...finalizados.map((p:any)=>p.numero)) : 0, totalPartidos: parts?.length||0};
}

async function getTabla(db: any, data: any) {
  return {ok:true, ...(await armarTabla(db, data.fechaId, data.pozoId))};
}

// Al cerrar y calcular: registra el/los ganadores de cada pozo; si empatan, se dividen el premio
async function registrarGanadores(db: any, fechaId: string) {
  const [{data: pozos}, {data: insc}, {data: cambios}] = await Promise.all([
    db.from("pozos").select("*").eq("fecha_id",fechaId),
    db.from("inscripciones").select("pozo_id,via_codigo").eq("fecha_id",fechaId).eq("estado_pago","Aprobado"),
    db.from("cambios_pagos").select("pozo_id,monto").eq("fecha_id",fechaId).in("estado",["Pagado","Usado"]),
  ]);
  await db.from("ganadores").delete().eq("fecha_id",fechaId);
  const filas: any[] = [];
  for (const pozo of (pozos||[])) {
    const {tabla} = await armarTabla(db, fechaId, pozo.id);
    const primeros = tabla.filter((u:any) => u.posicion === 1 && u.ptsTotal > 0);
    if (!primeros.length) continue;
    const {premio} = calcPremio(pozo, insc||[], cambios||[]);
    for (const u of primeros) filas.push({
      id:generarId("GAN"), fecha_id:fechaId, pozo_id:pozo.id, user_id:u.userId, usuario:u.siglas,
      puntos:u.ptsTotal, premio:Math.floor(premio/primeros.length), compartido_con:primeros.length,
    });
  }
  if (filas.length) await db.from("ganadores").insert(filas);
  return filas.length;
}

// ============================================================
//  NOTICIAS
// ============================================================
async function getNoticias(db: any) {
  const {data} = await db.from("config").select("valor").eq("clave","noticias").single();
  let noticias = [];
  try { noticias = JSON.parse(data?.valor||"[]"); } catch{}
  return {ok:true, noticias};
}

async function agregarNoticia(db: any, data: any) {
  const auth = await requireAuth(db, data);
  if (!auth.ok || auth.rol !== "Admin") return {ok:false, error:"Sin permisos"};
  const {data: cfg} = await db.from("config").select("valor").eq("clave","noticias").single();
  let noticias = [];
  try { noticias = JSON.parse(cfg?.valor||"[]"); } catch{}
  noticias.unshift({texto:data.texto.substring(0,300), fecha:data.fecha||""});
  if (noticias.length>10) noticias=noticias.slice(0,10);
  await db.from("config").update({valor:JSON.stringify(noticias)}).eq("clave","noticias");
  return {ok:true};
}

async function eliminarNoticia(db: any, data: any) {
  const auth = await requireAuth(db, data);
  if (!auth.ok || auth.rol !== "Admin") return {ok:false, error:"Sin permisos"};
  const {data: cfg} = await db.from("config").select("valor").eq("clave","noticias").single();
  let noticias = [];
  try { noticias = JSON.parse(cfg?.valor||"[]"); } catch{}
  noticias.splice(data.indice,1);
  await db.from("config").update({valor:JSON.stringify(noticias)}).eq("clave","noticias");
  return {ok:true};
}

// ============================================================
//  ADMIN — FECHAS
// ============================================================
async function adminCrearFecha(db: any, data: any) {
  const auth = await requireAuth(db, data);
  if (!auth.ok || auth.rol !== "Admin") return {ok:false, error:"Sin permisos"};
  const id = generarId("FECHA");
  const {error} = await db.from("fechas").insert({
    id, nombre:data.nombre, descripcion:data.descripcion||"",
    plazo_limite:data.plazoLimite, liga:data.liga||"",
    reglas_habilitadas:data.reglasHabilitadas||[],
    codigo_grupo: normalizarCodigo(data.codigoGrupo),
    pago_alias: String(data.pagoAlias||"").trim() || null, pago_titular: String(data.pagoTitular||"").trim() || null,
    empresa_id: data.empresaId || null, cambios_gratis: !!data.cambiosGratis,
  });
  if (error) return {ok:false, error: error.code === "23505" ? "Ese código ya lo usa otra fecha" : error.message};
  if (data.empresaId) {
    const {data: emp} = await db.from("empresas").select("nombre").eq("id", data.empresaId).single();
    await db.from("pozos").insert({id:generarId("POZ"), fecha_id:id, nombre:`Polla ${emp?.nombre||"Empresa"}`, monto:0, comision_pct:0, premio_fijo:0});
  }
  return {ok:true, fechaId:id};
}

async function adminEditarFecha(db: any, data: any) {
  const auth = await requireAuth(db, data);
  if (!auth.ok || auth.rol !== "Admin") return {ok:false, error:"Sin permisos"};
  const upd: any = {};
  if (data.nombre) upd.nombre = data.nombre;
  if (data.plazoLimite) upd.plazo_limite = data.plazoLimite;
  if (data.liga) upd.liga = data.liga;
  if (data.estado) upd.estado = data.estado;
  if (data.reglasHabilitadas) upd.reglas_habilitadas = data.reglasHabilitadas;
  if (data.codigoGrupo !== undefined) upd.codigo_grupo = normalizarCodigo(data.codigoGrupo);
  if (data.pagoAlias !== undefined) upd.pago_alias = String(data.pagoAlias||"").trim() || null;
  if (data.pagoTitular !== undefined) upd.pago_titular = String(data.pagoTitular||"").trim() || null;
  if (data.cambiosGratis !== undefined) upd.cambios_gratis = !!data.cambiosGratis;
  const {error} = await db.from("fechas").update(upd).eq("id",data.fechaId);
  if (error) return {ok:false, error: error.code === "23505" ? "Ese código ya lo usa otra fecha" : error.message};
  return {ok:true};
}

async function adminCerrarFecha(db: any, data: any) {
  const auth = await requireAuth(db, data);
  if (!auth.ok || auth.rol !== "Admin") return {ok:false, error:"Sin permisos"};
  await db.from("fechas").update({estado:"Cerrada"}).eq("id",data.fechaId);
  return {ok:true};
}

// ============================================================
//  ADMIN — POZOS
// ============================================================
async function adminCrearPozo(db: any, data: any) {
  const auth = await requireAuth(db, data);
  if (!auth.ok || auth.rol !== "Admin") return {ok:false, error:"Sin permisos"};
  const id = generarId("POZ");
  await db.from("pozos").insert({
    id, fecha_id:data.fechaId, nombre:data.nombre||(Number(data.monto)>0?`Pozo $${data.monto}`:"Pozo gratis"),
    monto:Number(data.monto)||0, comision_pct:Number(data.monto)>0?COMISION_PCT:0,
    premio_fijo: data.premioFijo ? Number(data.premioFijo) : null,
  });
  return {ok:true, pozoId:id};
}

// ============================================================
//  ADMIN — INGRESAR RESULTADO + CALCULAR PUNTAJES
// ============================================================
async function adminIngresarResultado(db: any, data: any) {
  const auth = await requireAuth(db, data);
  if (!auth.ok || auth.rol !== "Admin") return {ok:false, error:"Sin permisos"};

  const gL = parseInt(data.golesLocal), gV = parseInt(data.golesVisita);
  if (isNaN(gL)||isNaN(gV)) return {ok:false, error:"Goles inválidos"};
  const resultado = gL>gV?"L":gL===gV?"E":"V";

  const ids = await partidosGemelos(db, data.partidoId);
  for (const id of ids) {
    await db.from("partidos").update({
      estado:"Finalizado", goles_local:gL, goles_visita:gV,
      resultado, tarjetas_rojas:data.tarjetasRojas||0,
      ultimo_update:new Date().toISOString(),
    }).eq("id",id);
    // Calcular puntajes
    await calcularPuntajesPartido(db, id);
  }

  return {ok:true, resultado, enOtrasFechas: ids.length - 1};
}

// ============================================================
//  IMPORTAR PARTIDOS
// ============================================================
async function importarPartidos(db: any, data: any) {
  const auth = await requireAuth(db, data);
  if (!auth.ok || auth.rol !== "Admin") return {ok:false, error:"Sin permisos"};

  const {fechaId, partidosApi, tiposPartido} = data;
  const {data: fecha} = await db.from("fechas").select("cant_partidos").eq("id",fechaId).single();
  let numero = fecha?.cant_partidos || 0;
  const filas: any[] = [];

  for (const p of (partidosApi||[]).slice(0,20)) {
    numero++;
    const tipo = tiposPartido?.[p.apiId] || tiposPartido?.[numero] || "Normal";
    filas.push({
      id:generarId("PAR"), fecha_id:fechaId, numero, local:p.local, visita:p.visita,
      fecha_hora:p.fecha, liga:p.liga, liga_id:p.ligaId, partido_api_id:String(p.apiId),
      tipo, estado:"Pendiente", tarjetas_rojas:0,
      local_logo:p.localLogo||"", visita_logo:p.visitaLogo||"",
    });
  }

  if (filas.length) {
    await db.from("partidos").insert(filas);
    await db.from("fechas").update({cant_partidos:numero}).eq("id",fechaId);
  }

  return {ok:true, importados:filas.length};
}

// ============================================================
//  API FOOTBALL — Rondas y Partidos
// ============================================================
// Ligas del importador (ids de API-Football, verificadas el 2026-10-01 con temporada 2026 disponible)
const LIGA_IDS: Record<string,number> = {
  // Europa
  "Premier League":39, "La Liga":140, "Serie A":135, "Bundesliga":78, "Ligue 1":61, "Eredivisie":88, "Primeira Liga":94,
  // América
  "Liga Argentina":128, "Copa Argentina":130, "Brasileirão":71, "Liga MX":262, "MLS":253,
  "Primera Chile":265, "Primera Colombia":239, "Primera Uruguay":268,
  // Copas internacionales de clubes
  "Copa Libertadores":13, "Copa Sudamericana":11, "Champions League":2, "Europa League":3, "Conference League":848,
  // Selecciones
  "Mundial":1, "Eliminatorias Sudamérica":34, "Eliminatorias Europa":32, "Amistosos internacionales":10,
  "Nations League":5, "Copa América":9,
};
const TEMPORADA = 2026;
const AF_KEY = Deno.env.get("APIFOOTBALL_KEY") || "3ea8d01a35fbc69e57a1ea4ce7cf55e8";

async function callAPIFootball(endpoint: string, params: Record<string,any>) {
  const url = `https://v3.football.api-sports.io/${endpoint}?` + new URLSearchParams(
    Object.fromEntries(Object.entries(params).filter(([,v]) => v!=null).map(([k,v]) => [k,String(v)]))
  );
  const r = await fetch(url, {headers:{"x-apisports-key":AF_KEY}});
  return r.json();
}

function errorAPIFootball(res: any): string | null {
  const e = res?.errors;
  if (!e || (Array.isArray(e) && !e.length) || (typeof e === "object" && !Object.keys(e).length)) return null;
  const txt = typeof e === "string" ? e : Object.values(e).join(" ");
  if (/plan|season|access/i.test(txt)) return "Tu plan de API-Football no permite esa temporada. Con el plan gratis probá con 2024; para 2026 hay que contratar el plan pago.";
  if (/limit|request/i.test(txt)) return "Se alcanzó el límite de consultas de API-Football. Probá en un minuto.";
  return "API-Football: " + txt;
}

async function getRondas(db: any, data: any) {
  const ligaId = LIGA_IDS[data.liga];
  if (!ligaId) return {ok:false, error:"Liga no reconocida"};
  const res = await callAPIFootball("fixtures/rounds", {league:ligaId, season:data.temporada||TEMPORADA});
  const err = errorAPIFootball(res);
  if (err) return {ok:false, error:err};
  return {ok:true, rondas:res.response||[]};
}

async function buscarPorRonda(db: any, data: any) {
  const ligaId = LIGA_IDS[data.liga];
  if (!ligaId) return {ok:false, error:"Liga no reconocida"};
  const res = await callAPIFootball("fixtures", {league:ligaId, season:data.temporada||TEMPORADA, round:data.ronda, timezone:"America/Argentina/Buenos_Aires"});
  const err = errorAPIFootball(res);
  if (err) return {ok:false, error:err};
  const partidos = (res.response||[]).map((f:any) => ({
    apiId:f.fixture.id, fecha:f.fixture.date, local:f.teams.home.name, visita:f.teams.away.name,
    localLogo:f.teams.home.logo, visitaLogo:f.teams.away.logo,
    // Solo cuentan los 90 minutos: sin alargue ni penales
    golesLocal:f.score?.fulltime?.home ?? f.goals.home, golesVisita:f.score?.fulltime?.away ?? f.goals.away,
    liga:data.liga, ligaId, ronda:f.league.round,
  }));
  return {ok:true, partidos, ronda:data.ronda};
}

// ============================================================
//  ADMIN — USUARIOS
// ============================================================
async function adminGetUsuarios(db: any, data: any) {
  const auth = await requireAuth(db, data);
  if (!auth.ok || auth.rol !== "Admin") return {ok:false, error:"Sin permisos"};
  const {data: users} = await db.from("usuarios").select("id,telefono,usuario,nombre,alias_mp,email,estado,rol,empresa_id,created_at").order("created_at");
  return {ok:true, usuarios:users||[]};
}

// ============================================================
//  CALCULAR PUNTAJES (lógica completa)
// ============================================================
// TOLE: se fija UNA vez, al cierre de la fecha, con los pronósticos de ese momento (ninguna opción ≥45%).
// Después no cambia aunque haya cambios pagos. Se llama antes de cualquier cambio pago, grilla o cálculo.
async function fijarTole(db: any, fechaId: string) {
  const {data: fecha} = await db.from("fechas").select("id,plazo_limite,tole_fijado_at").eq("id",fechaId).single();
  if (!fecha || fecha.tole_fijado_at) return;
  const {data: parts} = await db.from("partidos").select("id,tipo,fecha_hora").eq("fecha_id",fechaId);
  if (minutosHasta(cierreFecha(fecha, parts||[])) > 0) return; // todavía no cerró
  // Marcar primero (evita que dos pedidos simultáneos lo calculen dos veces)
  const {data: marcado} = await db.from("fechas").update({tole_fijado_at:new Date().toISOString()}).eq("id",fechaId).is("tole_fijado_at",null).select("id");
  if (!marcado?.length) return;
  const {data: pronos} = await db.from("pronosticos").select("partido_id,pozo_id,pronostico").eq("fecha_id",fechaId);
  for (const p of (parts||[])) {
    if (p.tipo === "Polla") { await db.from("partidos").update({es_tole:false}).eq("id",p.id); continue; }
    const ps = (pronos||[]).filter((x:any) => x.partido_id === p.id);
    const t = ps.length || 1;
    const pct = (v:string) => ps.filter((x:any) => x.pronostico === v).length / t * 100;
    const tole = ps.length >= 3 && pct("L") < TOLE_UMBRAL && pct("E") < TOLE_UMBRAL && pct("V") < TOLE_UMBRAL;
    await db.from("partidos").update({es_tole: tole}).eq("id", p.id);
  }
}

async function calcularPuntajesPartido(db: any, partidoId: string) {
  const {data: p0} = await db.from("partidos").select("fecha_id").eq("id",partidoId).single();
  if (p0) await fijarTole(db, p0.fecha_id);
  const {data: part} = await db.from("partidos").select("*").eq("id",partidoId).single();
  if (!part||part.estado!=="Finalizado"||!part.resultado) return;

  const [{data:pronos},{data:reglas}] = await Promise.all([
    db.from("pronosticos").select("*").eq("partido_id",partidoId),
    db.from("reglas").select("*").eq("partido_id",partidoId),
  ]);

  const total = pronos?.length||1;
  const pctL=(pronos||[]).filter((p:any)=>p.pronostico==="L").length/total*100;
  const pctE=(pronos||[]).filter((p:any)=>p.pronostico==="E").length/total*100;
  const pctV=(pronos||[]).filter((p:any)=>p.pronostico==="V").length/total*100;
  // TOLE fijado al cierre. Reemplaza el valor del partido (Simple o Doble pasan a valer 3). La Polla vale siempre 5.
  const esTole = part.tipo!=="Polla" && !!part.es_tole;

  const puntajesUpsert: any[] = [];
  const reglasUpdate: any[] = [];

  for (const pr of (pronos||[])) {
    const acertado = pr.pronostico === part.resultado;
    let ptsN=0,ptsD=0,ptsP=0,ptsTole=0,ptsR=0;
    if (acertado) {
      if (part.tipo==="Polla") ptsP=PTS_POLLA;
      else if (esTole) ptsTole=TOLE_PTS;
      else if (part.tipo==="Doble") ptsD=PTS_DOBLE;
      else ptsN=PTS_NORMAL;
    }
    // Reglas: suman solas, sin importar el L/E/V (salvo La Rachita, que se calcula aparte con El Diego)
    const misReglas = (reglas||[]).filter((r:any)=>r.user_id===pr.user_id&&r.pozo_id===pr.pozo_id);
    for (const reg of misReglas) {
      if (reg.codigo==="LR" || reg.codigo==="DIEGO") { ptsR += reg.puntos_obtenidos||0; continue; }
      const pts = calcPtsRegla(reg, part.resultado, part.goles_local||0, part.goles_visita||0, part.tarjetas_rojas||0);
      ptsR += pts;
      reglasUpdate.push({id:reg.id, puntos_obtenidos:pts});
    }

    puntajesUpsert.push({
      id:generarId("PTS"), user_id:pr.user_id, usuario:pr.usuario,
      fecha_id:part.fecha_id, pozo_id:pr.pozo_id, partido_id:partidoId,
      numero_partido:part.numero, local:part.local, visita:part.visita,
      resultado_real:part.resultado, pronostico:pr.pronostico,
      acertado, pts_normal:ptsN, pts_doble:ptsD, pts_polla:ptsP,
      pts_tole:ptsTole, pts_reglas:ptsR, pts_total:ptsN+ptsD+ptsP+ptsTole+ptsR, es_tole:esTole,
    });
  }

  await Promise.all([
    ...(pronos||[]).map((pr:any) => db.from("pronosticos").update({acertado: pr.pronostico===part.resultado}).eq("id",pr.id)),
    puntajesUpsert.length ? db.from("puntajes").upsert(puntajesUpsert, {onConflict:"user_id,partido_id,pozo_id"}) : Promise.resolve(),
    ...reglasUpdate.map((r:any) => db.from("reglas").update({puntos_obtenidos:r.puntos_obtenidos}).eq("id",r.id)),
  ]);

  // La Rachita y El Diego dependen de varios partidos
  await calcularReglasMultiples(db, part.fecha_id);
}

function calcPtsRegla(reg:any, resultado:string, gL:number, gV:number, rojas:number): number {
  switch(reg.codigo) {
    case "LMR": return rojas;                                   // 1 por roja
    case "LLDG": return (gL+gV)>=5?4:0;                         // 5+ goles
    case "GSA": return (gL>0&&gV>0)?(gL+gV):0;                  // ambos anotan: 1 por gol
    case "ZPL": return Math.abs(gL-gV)>=3?4:0;                  // diferencia de 3+
    case "EQS": return resultado==="E"?3:0;                     // termina empatado
    case "MK": {                                                // resultado exacto
      const p=(reg.detalle||"").split("-").map(Number);
      return p.length===2&&p[0]===gL&&p[1]===gV?5:0;
    }
    default: return 0;
  }
}

// Recalcula la fila de puntaje de un partido sumando todas las reglas de ese jugador en ese partido
async function recomputarFila(db: any, userId: string, pozoId: string, partidoId: string) {
  const [{data: fila}, {data: regs}] = await Promise.all([
    db.from("puntajes").select("*").eq("user_id",userId).eq("pozo_id",pozoId).eq("partido_id",partidoId).single(),
    db.from("reglas").select("puntos_obtenidos").eq("user_id",userId).eq("pozo_id",pozoId).eq("partido_id",partidoId),
  ]);
  if (!fila) return;
  const ptsR = (regs||[]).reduce((t:number,r:any) => t+(r.puntos_obtenidos||0), 0);
  await db.from("puntajes").update({
    pts_reglas: ptsR,
    pts_total: (fila.pts_normal||0)+(fila.pts_doble||0)+(fila.pts_polla||0)+(fila.pts_tole||0)+ptsR,
  }).eq("id", fila.id);
}

const DIEGO_PTS = [0, 1, 3, 5]; // empates en sus 3 partidos: 1 → 1 pt, 2 → 3 pts, 3 → 5 pts

async function calcularReglasMultiples(db: any, fechaId: string) {
  const [{data:pronos},{data:reglas},{data:parts},{data:filas}] = await Promise.all([
    db.from("pronosticos").select("user_id,pozo_id,numero_partido,acertado,partido_id").eq("fecha_id",fechaId),
    db.from("reglas").select("*").eq("fecha_id",fechaId).in("codigo",["LR","DIEGO"]),
    db.from("partidos").select("id,estado,resultado").eq("fecha_id",fechaId),
    db.from("puntajes").select("user_id,pozo_id,partido_id").eq("fecha_id",fechaId),
  ]);
  const tieneFila = (u:string,z:string,p:string) => (filas||[]).some((f:any)=>f.user_id===u&&f.pozo_id===z&&f.partido_id===p);
  const tocadas = new Set<string>();

  const grupos: Record<string, any[]> = {};
  for (const r of (reglas||[])) (grupos[r.user_id+"|"+r.pozo_id+"|"+r.codigo] ||= []).push(r);

  for (const [key, regs] of Object.entries(grupos)) {
    const [userId, pozoId, codigo] = key.split("|");
    const asignar: Record<string, number> = {};
    regs.forEach((r:any) => asignar[r.id] = 0);

    if (codigo === "LR") {
      // Racha desde el partido elegido: 1 + 2 + 4 mientras acierte
      const ini = regs[0];
      const suspendidos = new Set((parts||[]).filter((p:any)=>p.estado==="Suspendido").map((p:any)=>p.id));
      const racha = (pronos||[]).filter((p:any)=>p.user_id===userId&&p.pozo_id===pozoId&&p.numero_partido>=ini.numero_partido&&!suspendidos.has(p.partido_id))
        .sort((a:any,b:any)=>a.numero_partido-b.numero_partido).slice(0,3);
      let pts = 0; const mult = [1,2,4];
      for (let i=0;i<racha.length;i++) { if (racha[i].acertado===true) pts+=mult[i]; else break; }
      asignar[ini.id] = pts;
    } else {
      // El Diego: cuántos de sus partidos terminaron empatados (independiente del L/E/V)
      const empates = regs.filter((r:any) => (parts||[]).find((p:any)=>p.id===r.partido_id&&p.estado==="Finalizado"&&p.resultado==="E")).length;
      const pts = DIEGO_PTS[Math.min(3, empates)];
      // Los puntos van a la fila del partido finalizado más reciente que tenga puntaje
      const conFila = regs.filter((r:any) => tieneFila(userId, pozoId, r.partido_id) && (parts||[]).find((p:any)=>p.id===r.partido_id&&p.estado==="Finalizado"));
      const destino = conFila.sort((a:any,b:any)=>b.numero_partido-a.numero_partido)[0];
      if (destino) asignar[destino.id] = pts;
    }

    for (const r of regs) {
      if ((r.puntos_obtenidos||0) !== asignar[r.id]) {
        await db.from("reglas").update({puntos_obtenidos: asignar[r.id]}).eq("id", r.id);
        tocadas.add(userId+"|"+pozoId+"|"+r.partido_id);
      }
    }
  }
  for (const t of tocadas) { const [u,z,p] = t.split("|"); await recomputarFila(db, u, z, p); }
}

// ============================================================
//  ACCIONES FALTANTES — agregadas
// ============================================================

// Estas se agregan al router en index.ts — copiar al switch en Deno.serve

// ============================================================
//  EDITAR PERFIL
// ============================================================
async function editarPerfil(db: any, data: any) {
  const auth = await requireAuth(db, data);
  if (!auth.ok) return auth;
  const upd: any = {};
  if (data.nombre) upd.nombre = data.nombre;
  if (data.alias) upd.alias_mp = data.alias;
  if (data.email) upd.email = data.email;
  if (data.avatar) {
    const a = String(data.avatar);
    const okEmoji = /^emoji:.{1,8}$/u.test(a);
    const okEscudo = /^escudo:https:\/\/media\.api-sports\.io\/football\/teams\/\d+\.png$/.test(a);
    if (!okEmoji && !okEscudo) return {ok:false, error:"Avatar inválido"};
    upd.avatar = a;
  }
  if (data.pin) {
    if (!PIN_OK(data.pin)) return {ok:false, error:"El PIN tiene que tener entre 4 y 8 números"};
    upd.pin_hash = await hashPinSeguro(String(data.pin));
  }
  await db.from("usuarios").update(upd).eq("id", auth.userId);
  return {ok:true};
}

// ============================================================
//  GET GRILLA (pronósticos de todos)
// ============================================================
async function getGrilla(db: any, data: any) {
  const {fechaId, pozoId} = data;
  const [{data: fecha}, {data: parts}] = await Promise.all([
    db.from("fechas").select("plazo_limite").eq("id",fechaId).single(),
    db.from("partidos").select("id,numero,local,visita,local_logo,visita_logo,resultado,goles_local,goles_visita,estado,tipo,fecha_hora").eq("fecha_id",fechaId).order("numero"),
  ]);
  // Los pronósticos de los demás se ven recién cuando cierra la fecha
  const cierre = cierreFecha(fecha, parts||[]);
  if (minutosHasta(cierre) > 0) return {ok:false, cerrada:false, abreEl: cierre?.toISOString(), error:"La grilla se abre cuando cierra la fecha"};
  await fijarTole(db, fechaId);
  const {data: toles} = await db.from("partidos").select("id,es_tole").eq("fecha_id",fechaId);
  for (const p of (parts||[])) p.es_tole = !!(toles||[]).find((t:any) => t.id === p.id && t.es_tole);

  const [{data: pronos}, {data: usuarios}, tablaRes] = await Promise.all([
    db.from("pronosticos").select("user_id,usuario,partido_id,pronostico,acertado,cambios_realizados").eq("fecha_id",fechaId).eq("pozo_id",pozoId),
    db.from("usuarios").select("id,nombre,usuario,avatar"),
    armarTabla(db, fechaId, pozoId),
  ]);
  const pos: Record<string,any> = {};
  for (const u of tablaRes.tabla) pos[u.userId] = u;
  const um: Record<string,any> = {};
  for (const u of (usuarios||[])) um[u.id] = u;

  const jugadores: Record<string,any> = {};
  for (const p of (pronos||[])) {
    const j = jugadores[p.user_id] ||= {userId:p.user_id, siglas:p.usuario||um[p.user_id]?.usuario, nombre:um[p.user_id]?.nombre||p.usuario, avatar:um[p.user_id]?.avatar||null,
      pronos:{}, cambiosUsados:0, ptsTotal:pos[p.user_id]?.ptsTotal||0, acertados:pos[p.user_id]?.acertados||0, ptsPartidos:pos[p.user_id]?.ptsPartidos||0, ptsReglas:pos[p.user_id]?.ptsReglas||0, posicion:pos[p.user_id]?.posicion||null};
    j.pronos[p.partido_id] = {v:p.pronostico, ok:p.acertado};
    j.cambiosUsados += p.cambios_realizados||0;
  }
  const lista = Object.values(jugadores).map((j:any) => ({...j, cambiosRestantes: Math.max(0, MAX_CAMBIOS - j.cambiosUsados)}))
    .sort((a:any,b:any) => (a.posicion||999)-(b.posicion||999) || b.ptsTotal-a.ptsTotal);
  return {ok:true, cerrada:true, partidos:parts||[], jugadores:lista};
}

// ============================================================
//  GET ESTADÍSTICAS
// ============================================================
async function getEstadisticas(db: any, data: any) {
  const [{data: users}, {data: inscripciones}, {data: fechas}] = await Promise.all([
    db.from("usuarios").select("id,usuario,nombre,rol,created_at").eq("estado","Activo"),
    db.from("inscripciones").select("user_id,fecha_id,pozo_id,estado_pago").eq("estado_pago","Aprobado"),
    db.from("fechas").select("id,nombre,estado").order("created_at"),
  ]);

  const {data: ganadores} = await db.from("ganadores").select("*");

  return {ok:true,
    totalUsuarios: users?.length||0,
    totalInscripciones: inscripciones?.length||0,
    fechas: (fechas||[]).map((f:any) => ({
      id:f.id, nombre:f.nombre, estado:f.estado,
      inscriptos:(inscripciones||[]).filter((i:any) => i.fecha_id===f.id).length,
    })),
    ganadores: ganadores||[],
  };
}

// ============================================================
//  ADMIN — CERRAR Y CALCULAR
// ============================================================
async function adminCerrarYCalcular(db: any, data: any) {
  const auth = await requireAuth(db, data);
  if (!auth.ok || auth.rol !== "Admin") return {ok:false, error:"Sin permisos"};

  await db.from("fechas").update({estado:"Cerrada"}).eq("id",data.fechaId);

  const {data: parts} = await db.from("partidos")
    .select("id").eq("fecha_id",data.fechaId).eq("estado","Finalizado");

  for (const p of (parts||[])) {
    await calcularPuntajesPartido(db, p.id);
  }
  const ganadores = await registrarGanadores(db, data.fechaId);

  return {ok:true, calculados:parts?.length||0, ganadores};
}

// ============================================================
//  ADMIN — HABILITAR MANUAL
// ============================================================
async function adminHabilitarManual(db: any, data: any) {
  const auth = await requireAuth(db, data);
  if (!auth.ok || auth.rol !== "Admin") return {ok:false, error:"Sin permisos"};

  await db.from("inscripciones").update({estado_pago:"Aprobado", habilitado:true})
    .eq("id", data.inscripcionId);

  return {ok:true};
}

// ============================================================
//  ADMIN — CAMBIAR ESTADO USUARIO
// ============================================================
async function adminCambiarEstado(db: any, data: any) {
  const auth = await requireAuth(db, data);
  if (!auth.ok || auth.rol !== "Admin") return {ok:false, error:"Sin permisos"};

  await db.from("usuarios").update({estado: data.estado}).eq("id", data.userId);
  return {ok:true};
}

// ============================================================
//  ADMIN — GET INSCRIPCIONES PENDIENTES
// ============================================================
async function adminGetInscripcionesPendientes(db: any, data: any) {
  const auth = await requireAuth(db, data);
  if (!auth.ok || auth.rol !== "Admin") return {ok:false, error:"Sin permisos"};

  const {data: insc} = await db.from("inscripciones")
    .select("*, usuarios(nombre,telefono,alias_mp), fechas(nombre), pozos(nombre,monto)")
    .eq("estado_pago","Pendiente")
    .order("created_at");

  return {ok:true, inscripciones:(insc||[]).map((i:any) => ({
    id:i.id, userId:i.user_id, nombre:i.usuarios?.nombre, telefono:i.usuarios?.telefono,
    alias:i.usuarios?.alias_mp, fechaNombre:i.fechas?.nombre, pozoNombre:i.pozos?.nombre,
    monto:i.pozos?.monto, created_at:i.created_at,
  }))};
}

// ============================================================
//  GET GRUPO POR CÓDIGO
// ============================================================
function normalizarCodigo(c: any): string | null {
  const v = String(c || "").trim().toUpperCase().replace(/\s+/g, "");
  return v || null;
}

async function fechaPorCodigo(db: any, codigo: any) {
  const c = normalizarCodigo(codigo);
  if (!c) return null;
  const {data} = await db.from("fechas").select("*").eq("codigo_grupo", c).single();
  return data;
}

async function getGrupoPorCodigo(db: any, data: any) {
  const fecha = await fechaPorCodigo(db, data.codigo);
  if (fecha) {
    const {data: pozos} = await db.from("pozos").select("id,nombre,monto").eq("fecha_id",fecha.id).eq("estado","Activo").order("monto");
    const pozo = (pozos||[]).find((p:any) => p.id === data.pozoId) || pozos?.[0];
    if (!pozo) return {ok:false, error:"Esa fecha todavía no tiene pozos"};
    return {ok:true, grupo:{
      id:fecha.id, nombre:fecha.nombre, codigo:fecha.codigo_grupo,
      fechaId:fecha.id, pozoId:pozo.id, fechaNombre:fecha.nombre, pozoNombre:pozo.nombre, monto:pozo.monto,
      cerrado:true,
    }};
  }
  const {data: grupo} = await db.from("grupos")
    .select("*, fechas(nombre), pozos(nombre,monto)")
    .eq("codigo", data.codigo).single();

  if (!grupo) return {ok:false, error:"Código inválido"};
  return {ok:true, grupo:{
    id:grupo.id, nombre:grupo.nombre, codigo:grupo.codigo,
    fechaId:grupo.fecha_id, pozoId:grupo.pozo_id,
    fechaNombre:grupo.fechas?.nombre, pozoNombre:grupo.pozos?.nombre, monto:grupo.pozos?.monto,
    cantMiembros:grupo.cant_miembros,
  }};
}

// ============================================================
//  CAMBIOS PAGOS
//  Flujo: solicitarCambio (Pendiente) → crearPreferenciaCambio (link MP)
//  → vuelve con ?cambio=ok&id=... → ejecutarCambio (verifica pago en MP,
//  Pagado → Usado y actualiza el pronóstico)
// ============================================================
const COSTO_CAMBIO: Record<number, number> = {1: 20, 2: 25, 3: 30};

// Cambios gratis e ilimitados hasta 1 hora antes del PRIMER partido de la fecha; después, cambios pagos.
function libreHasta(parts: any[], fecha?: any): Date | null { return cierreFecha(fecha, parts); }
function enPeriodoLibre(parts: any[], fecha?: any): boolean { return minutosHasta(cierreFecha(fecha, parts)) > 0; }

async function infoCambios(db: any, userId: string, fechaId: string, pozoId: string) {
  const [{data: pronos}, {data: pozo}, {data: fe}] = await Promise.all([
    db.from("pronosticos").select("cambios_realizados").eq("user_id",userId).eq("fecha_id",fechaId).eq("pozo_id",pozoId),
    db.from("pozos").select("monto").eq("id",pozoId).single(),
    db.from("fechas").select("empresa_id,cambios_gratis").eq("id",fechaId).single(),
  ]);
  const gratis = !!(fe?.empresa_id || fe?.cambios_gratis || !Number(pozo?.monto));
  const cambiosUsados = (pronos||[]).reduce((t:number,p:any) => t+(p.cambios_realizados||0), 0);
  const proximoCambio = cambiosUsados + 1;
  const proximoPorcentaje = COSTO_CAMBIO[proximoCambio] || 30;
  return {
    cambiosUsados,
    cambiosRestantes: Math.max(0, MAX_CAMBIOS - cambiosUsados),
    proximoCambio, proximoPorcentaje,
    proximoCosto: gratis ? 0 : Math.round((pozo?.monto||0) * proximoPorcentaje / 100), gratis,
  };
}

async function getMisCambios(db: any, data: any) {
  const auth = await requireAuth(db, data);
  if (!auth.ok) return auth;
  const {fechaId, pozoId} = data;
  if (!fechaId || !pozoId) return {ok:false, error:"Faltan datos"};

  const [info, {data: cambios}] = await Promise.all([
    infoCambios(db, auth.userId!, fechaId, pozoId),
    db.from("cambios_pagos").select("*").eq("user_id",auth.userId).eq("fecha_id",fechaId).eq("pozo_id",pozoId).order("created_at"),
  ]);
  return {ok:true, ...info, cambios:(cambios||[]).map((c:any) => ({
    id:c.id, partidoId:c.partido_id, numero:c.numero_partido, local:c.local, visita:c.visita,
    de:c.pronostico_anterior, a:c.pronostico_nuevo, numeroCambio:c.numero_cambio,
    porcentaje:c.porcentaje, monto:c.monto, estado:c.estado,
  }))};
}

async function solicitarCambio(db: any, data: any) {
  const auth = await requireAuth(db, data);
  if (!auth.ok) return auth;
  const {fechaId, pozoId, partidoId, pronosticoNuevo} = data;
  if (!fechaId || !pozoId || !partidoId || !["L","E","V"].includes(pronosticoNuevo)) return {ok:false, error:"Faltan datos"};

  const [{data: insc}, {data: part}, {data: prono}] = await Promise.all([
    db.from("inscripciones").select("id").eq("user_id",auth.userId).eq("fecha_id",fechaId).eq("pozo_id",pozoId).or("estado_pago.eq.Aprobado,and(estado_pago.eq.Pendiente,comprobante_path.not.is.null)").limit(1).maybeSingle(),
    db.from("partidos").select("*").eq("id",partidoId).eq("fecha_id",fechaId).single(),
    db.from("pronosticos").select("*").eq("user_id",auth.userId).eq("partido_id",partidoId).eq("pozo_id",pozoId).single(),
  ]);
  if (!insc) return {ok:false, error:"No habilitado"};
  if (!part) return {ok:false, error:"Partido no encontrado"};
  if (!prono) return {ok:false, error:"No tenés pronóstico en ese partido para cambiar"};
  const {data: partsFecha} = await db.from("partidos").select("fecha_hora").eq("fecha_id",fechaId);
  const {data: fechaSC} = await db.from("fechas").select("plazo_limite,empresa_id").eq("id",fechaId).single();
  if (enPeriodoLibre(partsFecha||[], fechaSC)) return {ok:false, error:"Todavía estás en el período de cambios gratis: tocá directamente el pronóstico nuevo"};
  if (prono.pronostico === pronosticoNuevo) return {ok:false, error:"Es el mismo pronóstico"};
  if (part.estado === "Finalizado" || part.estado === "Suspendido") return {ok:false, error:"Partido cerrado"};
  if (part.fecha_hora && (new Date(part.fecha_hora).getTime() - Date.now()) / 60000 <= MINUTOS_CIERRE_CAMBIO) return {ok:false, error:"Los cambios de este partido cerraron 1 hora antes del comienzo"};

  const info = await infoCambios(db, auth.userId!, fechaId, pozoId);
  if (info.cambiosRestantes <= 0) return {ok:false, error:"Ya usaste los 3 cambios permitidos"};

  // Un solo cambio abierto por partido: si había uno sin pagar, se cancela
  await db.from("cambios_pagos").update({estado:"Cancelado"})
    .eq("user_id",auth.userId).eq("partido_id",partidoId).eq("pozo_id",pozoId).eq("estado","Pendiente");
  const {data: pagado} = await db.from("cambios_pagos").select("id")
    .eq("user_id",auth.userId).eq("partido_id",partidoId).eq("pozo_id",pozoId).eq("estado","Pagado").single();
  if (pagado) return {ok:false, error:"Ya tenés un cambio pagado sin usar en ese partido"};

  const id = generarId("CAM");
  const {error} = await db.from("cambios_pagos").insert({
    id, user_id:auth.userId, usuario:prono.usuario, fecha_id:fechaId, pozo_id:pozoId, partido_id:partidoId,
    numero_partido:part.numero, local:part.local, visita:part.visita,
    pronostico_anterior:prono.pronostico, pronostico_nuevo:pronosticoNuevo,
    numero_cambio:info.proximoCambio, porcentaje:info.proximoPorcentaje, monto:info.proximoCosto,
  });
  if (error) return {ok:false, error:error.message};
  // Empresas y pozos gratis: el cambio no se paga y se aplica al instante (igual cuenta para el límite de 3)
  if (fechaSC?.empresa_id || !Number(info.proximoCosto)) {
    await db.from("cambios_pagos").update({monto:0, porcentaje:0, estado:"Pagado", mp_status:"empresa", pagado_at:new Date().toISOString()}).eq("id",id);
    const {data: cam} = await db.from("cambios_pagos").select("*").eq("id",id).single();
    const r = await aplicarCambio(db, cam);
    return {ok:r.ok, aplicado:true, mensaje:r.mensaje, error:r.error, numeroCambio:info.proximoCambio};
  }
  return {ok:true, cambioId:id, monto:info.proximoCosto, porcentaje:info.proximoPorcentaje, numeroCambio:info.proximoCambio};
}

async function crearPreferenciaCambio(db: any, data: any) {
  const auth = await requireAuth(db, data);
  if (!auth.ok) return auth;
  const MP_TOKEN = Deno.env.get("MP_ACCESS_TOKEN");

  const {data: cambio} = await db.from("cambios_pagos").select("*").eq("id",data.cambioId).eq("user_id",auth.userId).single();
  if (!cambio) return {ok:false, error:"Cambio no encontrado"};
  if (cambio.estado !== "Pendiente") return {ok:false, error:"Ese cambio ya no está pendiente"};

  // Sin MercadoPago configurado: modo prueba (el pago se simula con pagarCambioPrueba)
  if (!MP_TOKEN) return {ok:true, modoPrueba:true, cambioId:cambio.id, monto:cambio.monto, numeroCambio:cambio.numero_cambio, porcentaje:cambio.porcentaje};

  const APP_URL = Deno.env.get("APP_URL") || "https://gr10-cdu.github.io/PollaProdes/";
  const mpResp = await fetch("https://api.mercadopago.com/checkout/preferences", {
    method:"POST",
    headers:{"Content-Type":"application/json","Authorization":`Bearer ${MP_TOKEN}`},
    body:JSON.stringify({
      items:[{title:`Polla Prodes — Cambio #${cambio.numero_cambio} — ${cambio.local} vs ${cambio.visita}`, quantity:1, unit_price:cambio.monto, currency_id:"ARS"}],
      back_urls:{success:`${APP_URL}?cambio=ok&id=${cambio.id}`,failure:`${APP_URL}?cambio=error`,pending:`${APP_URL}?cambio=pendiente`},
      auto_return:"approved",
      external_reference:`CAMBIO:${cambio.id}`,
      notification_url: `${SUPABASE_URL}/functions/v1/api?webhook=mp`,
    }),
  });
  const mpData = await mpResp.json();
  if (!mpData.id) return {ok:false, error:"Error MP"};
  await db.from("cambios_pagos").update({mp_preference_id:mpData.id}).eq("id",cambio.id);
  return {ok:true, preferenceId:mpData.id, initPoint:mpData.init_point, sandboxUrl:mpData.sandbox_init_point};
}

// Consulta a MercadoPago si el cambio tiene un pago aprobado (no dependemos del webhook)
async function verificarPagoCambio(db: any, cambio: any): Promise<boolean> {
  const MP_TOKEN = Deno.env.get("MP_ACCESS_TOKEN");
  if (!MP_TOKEN) return false;
  const r = await fetch(`https://api.mercadopago.com/v1/payments/search?external_reference=${encodeURIComponent("CAMBIO:"+cambio.id)}`,
    {headers:{"Authorization":`Bearer ${MP_TOKEN}`}});
  const res = await r.json();
  const aprobado = (res.results||[]).find((p:any) => p.status === "approved");
  if (!aprobado) return false;
  await db.from("cambios_pagos").update({
    estado:"Pagado", mp_payment_id:String(aprobado.id), mp_status:aprobado.status, pagado_at:new Date().toISOString(),
  }).eq("id",cambio.id).eq("estado","Pendiente");
  return true;
}

async function aplicarCambio(db: any, cambio: any) {
  await fijarTole(db, cambio.fecha_id);
  const {data: prono} = await db.from("pronosticos").select("*")
    .eq("user_id",cambio.user_id).eq("partido_id",cambio.partido_id).eq("pozo_id",cambio.pozo_id).single();
  if (!prono) return {ok:false, error:"Pronóstico no encontrado"};
  await db.from("pronosticos").update({
    pronostico:cambio.pronostico_nuevo,
    cambios_realizados:(prono.cambios_realizados||0)+1,
    updated_at:new Date().toISOString(),
  }).eq("id",prono.id);
  await db.from("cambios_pagos").update({estado:"Usado", ejecutado_at:new Date().toISOString()}).eq("id",cambio.id);
  return {ok:true, mensaje:`Cambio aplicado: ${cambio.local} vs ${cambio.visita} → ${cambio.pronostico_nuevo}`};
}

async function ejecutarCambio(db: any, data: any) {
  const auth = await requireAuth(db, data);
  if (!auth.ok) return auth;
  const {data: cambio} = await db.from("cambios_pagos").select("*").eq("id",data.cambioId).eq("user_id",auth.userId).single();
  if (!cambio) return {ok:false, error:"Cambio no encontrado"};
  if (cambio.estado === "Usado") return {ok:true, mensaje:"El cambio ya estaba aplicado"};
  if (cambio.estado === "Pendiente" && !(await verificarPagoCambio(db, cambio))) {
    return {ok:false, error:"Todavía no vemos el pago aprobado. Probá de nuevo en un rato."};
  }
  if (!["Pendiente","Pagado"].includes(cambio.estado)) return {ok:false, error:`Cambio ${cambio.estado.toLowerCase()}`};
  // Si el partido ya cerró, el cambio queda Pagado para que el admin lo resuelva
  const {data: part} = await db.from("partidos").select("estado,fecha_hora").eq("id",cambio.partido_id).single();
  if (part?.estado === "Finalizado" || (part?.fecha_hora && (new Date(part.fecha_hora).getTime() - Date.now()) / 60000 <= MINUTOS_CIERRE_CAMBIO)) {
    const dev = await devolverPagoCambio(db, cambio.id);
    return {ok:false, error: dev ? "El partido ya cerró: el cambio no se aplicó y te devolvemos el pago." : "El partido ya cerró: el cambio no se aplicó. La devolución del pago quedó pendiente con el admin."};
  }
  return await aplicarCambio(db, cambio);
}

async function adminHabilitarCambio(db: any, data: any) {
  const auth = await requireAuth(db, data);
  if (!auth.ok || auth.rol !== "Admin") return {ok:false, error:"Sin permisos"};
  if (Deno.env.get("MP_ACCESS_TOKEN")) return {ok:false, error:"Con MercadoPago activo los cambios solo se habilitan pagando"};
  const {data: cambio} = await db.from("cambios_pagos").select("*").eq("id",data.cambioId).single();
  if (!cambio) return {ok:false, error:"Cambio no encontrado"};
  if (!["Pendiente","Pagado"].includes(cambio.estado)) return {ok:false, error:`Cambio ${cambio.estado.toLowerCase()}`};
  return await aplicarCambio(db, cambio);
}

// ============================================================
//  UNIRSE CON CÓDIGO DE GRUPO CERRADO
//  Quien tiene el código de la fecha queda inscripto y habilitado sin pagar.
// ============================================================
async function unirseConCodigo(db: any, data: any) {
  const auth = await requireAuth(db, data);
  if (!auth.ok) return auth;

  const fecha = await fechaPorCodigo(db, data.codigo);
  if (!fecha) return {ok:false, error:"Código inválido"};
  if (fecha.estado !== "Abierta") return {ok:false, error:"Esa fecha ya está cerrada"};
  const {data: partsF} = await db.from("partidos").select("fecha_hora").eq("fecha_id", fecha.id);
  if (minutosHasta(cierreFecha(fecha, partsF||[])) <= 0) return {ok:false, error:"La fecha ya cerró (1 hora antes del primer partido)"};

  const {data: pozos} = await db.from("pozos").select("id").eq("fecha_id",fecha.id).eq("estado","Activo").order("monto");
  const pozo = (pozos||[]).find((p:any) => p.id === data.pozoId) || pozos?.[0];
  if (!pozo) return {ok:false, error:"Esa fecha todavía no tiene pozos"};

  const {data: ya} = await db.from("inscripciones").select("id,estado_pago")
    .eq("user_id",auth.userId).eq("pozo_id",pozo.id).in("estado_pago",["Pendiente","Aprobado"]).single();
  if (ya) {
    if (ya.estado_pago !== "Aprobado") {
      await db.from("inscripciones").update({estado_pago:"Aprobado", habilitado:true, pagado_at:new Date().toISOString(), via_codigo:true}).eq("id",ya.id);
    }
    return {ok:true, fechaId:fecha.id, pozoId:pozo.id, inscripcionId:ya.id};
  }

  const {data: user} = await db.from("usuarios").select("usuario").eq("id",auth.userId).single();
  const id = generarId("INS");
  const {error} = await db.from("inscripciones").insert({
    id, user_id:auth.userId, usuario:user?.usuario, fecha_id:fecha.id, pozo_id:pozo.id,
    estado_pago:"Aprobado", habilitado:true, pagado_at:new Date().toISOString(), via_codigo:true,
  });
  if (error) return {ok:false, error:error.message};
  return {ok:true, fechaId:fecha.id, pozoId:pozo.id, inscripcionId:id};
}

// ============================================================
//  PAGO DE PRUEBA (solo mientras MercadoPago no está configurado)
//  Marca el cambio como pagado con un id "PRUEBA-..." y lo aplica.
// ============================================================
async function pagarCambioPrueba(db: any, data: any) {
  const auth = await requireAuth(db, data);
  if (!auth.ok) return auth;
  if (Deno.env.get("MP_ACCESS_TOKEN")) return {ok:false, error:"MercadoPago ya está configurado: el pago de prueba está desactivado"};

  const {data: cambio} = await db.from("cambios_pagos").select("*").eq("id",data.cambioId).eq("user_id",auth.userId).single();
  if (!cambio) return {ok:false, error:"Cambio no encontrado"};
  if (cambio.estado === "Pendiente") {
    await db.from("cambios_pagos").update({
      estado:"Pagado", mp_payment_id:"PRUEBA-"+Date.now(), mp_status:"prueba", pagado_at:new Date().toISOString(),
    }).eq("id",cambio.id).eq("estado","Pendiente");
  }
  return await ejecutarCambio(db, data);
}

// Devolución de un cambio pagado tarde (el partido ya había cerrado)
async function devolverPagoCambio(db: any, cambioId: string): Promise<boolean> {
  const {data: c} = await db.from("cambios_pagos").select("*").eq("id",cambioId).single();
  if (!c) return false;
  const MP_TOKEN = Deno.env.get("MP_ACCESS_TOKEN");
  let ok = false;
  if (String(c.mp_payment_id||"").startsWith("PRUEBA-")) ok = true;
  else if (MP_TOKEN && c.mp_payment_id) {
    try {
      const r = await fetch(`https://api.mercadopago.com/v1/payments/${c.mp_payment_id}/refunds`, {
        method:"POST", headers:{"Authorization":`Bearer ${MP_TOKEN}`, "Content-Type":"application/json", "X-Idempotency-Key": "dev-"+c.id},
        body:"{}",
      });
      ok = r.ok;
    } catch (e) { console.error("refund", e); }
  }
  await db.from("cambios_pagos").update({estado:"Vencido", mp_status: ok ? "devuelto" : "devolucion_pendiente"}).eq("id",c.id);
  return ok;
}

// ============================================================
//  ADMIN — ESTADO DEL PARTIDO
//  Suspendido: no suma para nadie (se borran sus puntos).
//  Postergado: queda en espera; el admin decide después (carga resultado o lo suspende).
//  Pendiente: vuelve a la normalidad.
// ============================================================
async function adminEstadoPartido(db: any, data: any) {
  const auth = await requireAuth(db, data);
  if (!auth.ok || auth.rol !== "Admin") return {ok:false, error:"Sin permisos"};
  const {partidoId, estado} = data;
  if (!["Suspendido","Postergado","Pendiente"].includes(estado)) return {ok:false, error:"Estado inválido"};
  const ids = await partidosGemelos(db, partidoId);
  for (const id of ids) await estadoPartidoUno(db, id, estado);
  return {ok:true, estado, enOtrasFechas: ids.length - 1};
}
async function estadoPartidoUno(db: any, partidoId: string, estado: string) {
  const {data: part} = await db.from("partidos").select("id,fecha_id").eq("id",partidoId).single();
  if (!part) return;
  await db.from("partidos").update({
    estado, resultado:null, goles_local:null, goles_visita:null, tarjetas_rojas:0, ultimo_update:new Date().toISOString(),
  }).eq("id",partidoId);
  // Sacar cualquier punto que haya tenido
  await Promise.all([
    db.from("puntajes").delete().eq("partido_id",partidoId),
    db.from("pronosticos").update({acertado:null}).eq("partido_id",partidoId),
    db.from("reglas").update({puntos_obtenidos:0}).eq("partido_id",partidoId),
  ]);
  await calcularReglasMultiples(db, part.fecha_id);
}

// ============================================================
//  FOTO DE PERFIL (queda pendiente hasta que la aprueba el admin)
//  Se guarda en Storage, bucket público "avatares". Formato de avatar: "foto:<url>".
// ============================================================
const BUCKET = "avatares";
async function asegurarBucket(db: any) {
  const {data} = await db.storage.getBucket(BUCKET);
  if (!data) await db.storage.createBucket(BUCKET, {public:true, fileSizeLimit: 500*1024, allowedMimeTypes:["image/jpeg","image/png","image/webp"]});
}
const rutaDe = (url: string) => (url||"").split(`/object/public/${BUCKET}/`)[1] || null;

async function subirFoto(db: any, data: any) {
  const auth = await requireAuth(db, data);
  if (!auth.ok) return auth;
  const m = /^data:image\/(jpeg|png|webp);base64,(.+)$/.exec(String(data.imagen||""));
  if (!m) return {ok:false, error:"Imagen inválida"};
  const bytes = Uint8Array.from(atob(m[2]), c => c.charCodeAt(0));
  if (bytes.length > 500*1024) return {ok:false, error:"La foto es muy pesada (máximo 500 KB)"};
  await asegurarBucket(db);
  const {data: u} = await db.from("usuarios").select("foto_pendiente").eq("id",auth.userId).single();
  const ext = m[1] === "jpeg" ? "jpg" : m[1];
  const ruta = `pendientes/${auth.userId}-${crypto.randomUUID()}.${ext}`;
  const up = await db.storage.from(BUCKET).upload(ruta, bytes, {contentType:`image/${m[1]}`, upsert:false});
  if (up.error) return {ok:false, error:"No se pudo subir la foto: "+up.error.message};
  if (u?.foto_pendiente && rutaDe(u.foto_pendiente)) await db.storage.from(BUCKET).remove([rutaDe(u.foto_pendiente)]);
  const url = db.storage.from(BUCKET).getPublicUrl(ruta).data.publicUrl;
  await db.from("usuarios").update({foto_pendiente:url, foto_enviada_at:new Date().toISOString()}).eq("id",auth.userId);
  return {ok:true, fotoPendiente:url};
}

async function cancelarFoto(db: any, data: any) {
  const auth = await requireAuth(db, data);
  if (!auth.ok) return auth;
  const {data: u} = await db.from("usuarios").select("foto_pendiente").eq("id",auth.userId).single();
  if (u?.foto_pendiente && rutaDe(u.foto_pendiente)) await db.storage.from(BUCKET).remove([rutaDe(u.foto_pendiente)]);
  await db.from("usuarios").update({foto_pendiente:null, foto_enviada_at:null}).eq("id",auth.userId);
  return {ok:true};
}

async function adminGetFotosPendientes(db: any, data: any) {
  const auth = await requireAuth(db, data);
  if (!auth.ok || auth.rol !== "Admin") return {ok:false, error:"Sin permisos"};
  const {data: us} = await db.from("usuarios").select("id,usuario,nombre,avatar,foto_pendiente,foto_enviada_at").not("foto_pendiente","is",null).order("foto_enviada_at");
  return {ok:true, fotos:(us||[]).map((u:any) => ({userId:u.id, usuario:u.usuario, nombre:u.nombre, avatar:u.avatar, foto:u.foto_pendiente, enviada:u.foto_enviada_at}))};
}

async function adminResolverFoto(db: any, data: any) {
  const auth = await requireAuth(db, data);
  if (!auth.ok || auth.rol !== "Admin") return {ok:false, error:"Sin permisos"};
  const {data: u} = await db.from("usuarios").select("id,avatar,foto_pendiente").eq("id",data.userId).single();
  if (!u?.foto_pendiente) return {ok:false, error:"No hay foto pendiente"};
  if (data.aprobar) {
    // Si tenía una foto aprobada antes, se borra
    if (String(u.avatar||"").startsWith("foto:") && rutaDe(u.avatar.slice(5))) await db.storage.from(BUCKET).remove([rutaDe(u.avatar.slice(5))]);
    await db.from("usuarios").update({avatar:"foto:"+u.foto_pendiente, foto_pendiente:null, foto_enviada_at:null}).eq("id",u.id);
  } else {
    if (rutaDe(u.foto_pendiente)) await db.storage.from(BUCKET).remove([rutaDe(u.foto_pendiente)]);
    await db.from("usuarios").update({foto_pendiente:null, foto_enviada_at:null}).eq("id",u.id);
  }
  return {ok:true};
}

// ============================================================
//  MERCADOPAGO: verificación de pagos (aviso automático + vuelta del jugador)
//  Nunca se confía en lo que llega: siempre se consulta el pago a la API de MercadoPago.
// ============================================================
async function aprobarInscripcionPagada(db: any, inscId: string, pago: any) {
  await db.from("inscripciones").update({
    estado_pago:"Aprobado", habilitado:true, mp_payment_id:String(pago.id), pagado_at:new Date().toISOString(),
  }).eq("id", inscId).eq("estado_pago","Pendiente");
}

async function webhookMP(db: any, req: Request) {
  const MP_TOKEN = Deno.env.get("MP_ACCESS_TOKEN");
  if (!MP_TOKEN) return;
  const url = new URL(req.url);
  let body: any = {};
  try { body = await req.json(); } catch {}
  const tipo = body.type || body.topic || url.searchParams.get("type") || url.searchParams.get("topic");
  const id = body.data?.id || url.searchParams.get("data.id") || url.searchParams.get("id");
  if (tipo !== "payment" || !id) return;
  const r = await fetch(`https://api.mercadopago.com/v1/payments/${id}`, {headers:{"Authorization":`Bearer ${MP_TOKEN}`}});
  if (!r.ok) return;
  const pago = await r.json();
  if (pago.status !== "approved") return;
  const ref = String(pago.external_reference || "");
  if (ref.startsWith("CAMBIO:")) {
    const cambioId = ref.slice(7);
    await db.from("cambios_pagos").update({
      estado:"Pagado", mp_payment_id:String(pago.id), mp_status:pago.status, pagado_at:new Date().toISOString(),
    }).eq("id",cambioId).eq("estado","Pendiente");
    const {data: cambio} = await db.from("cambios_pagos").select("*").eq("id",cambioId).single();
    if (cambio?.estado === "Pagado") {
      const {data: part} = await db.from("partidos").select("estado,fecha_hora").eq("id",cambio.partido_id).single();
      const cerrado = part?.estado === "Finalizado" || (part?.fecha_hora && (new Date(part.fecha_hora).getTime() - Date.now()) / 60000 <= MINUTOS_CIERRE_CAMBIO);
      if (cerrado) await devolverPagoCambio(db, cambioId); else await aplicarCambio(db, cambio);
    }
  } else if (ref) {
    await aprobarInscripcionPagada(db, ref, pago);
  }
}

async function verificarPagoInscripcion(db: any, data: any) {
  const auth = await requireAuth(db, data);
  if (!auth.ok) return auth;
  const {data: insc} = await db.from("inscripciones").select("*").eq("id",data.inscripcionId).eq("user_id",auth.userId).single();
  if (!insc) return {ok:false, error:"Inscripción no encontrada"};
  if (insc.estado_pago === "Aprobado") return {ok:true, aprobado:true, fechaId:insc.fecha_id, pozoId:insc.pozo_id};
  const MP_TOKEN = Deno.env.get("MP_ACCESS_TOKEN");
  if (!MP_TOKEN) return {ok:false, error:"MercadoPago no configurado"};
  const r = await fetch(`https://api.mercadopago.com/v1/payments/search?external_reference=${encodeURIComponent(insc.id)}`, {headers:{"Authorization":`Bearer ${MP_TOKEN}`}});
  const res = await r.json();
  const pago = (res.results||[]).find((p:any) => p.status === "approved");
  if (!pago) return {ok:true, aprobado:false};
  await aprobarInscripcionPagada(db, insc.id, pago);
  return {ok:true, aprobado:true, fechaId:insc.fecha_id, pozoId:insc.pozo_id};
}

// ============================================================
//  PAGO POR TRANSFERENCIA CON COMPROBANTE
//  La app no procesa pagos: el jugador transfiere al alias/CVU, sube el comprobante
//  y el admin lo aprueba. Los comprobantes van a un bucket PRIVADO.
// ============================================================
const BUCKET_COMP = "comprobantes";
async function asegurarBucketComp(db: any) {
  const {data} = await db.storage.getBucket(BUCKET_COMP);
  if (!data) await db.storage.createBucket(BUCKET_COMP, {public:false, fileSizeLimit: 3*1024*1024, allowedMimeTypes:["image/jpeg","image/png","image/webp"]});
}
async function subirComprobante(db: any, userId: string, imagen: string): Promise<{path?:string, error?:string}> {
  const m = /^data:image\/(jpeg|png|webp);base64,(.+)$/.exec(String(imagen||""));
  if (!m) return {error:"Imagen inválida"};
  const bytes = Uint8Array.from(atob(m[2]), c => c.charCodeAt(0));
  if (bytes.length > 3*1024*1024) return {error:"El comprobante es muy pesado (máximo 3 MB)"};
  await asegurarBucketComp(db);
  const path = `${userId}/${Date.now()}-${crypto.randomUUID().slice(0,8)}.${m[1]==="jpeg"?"jpg":m[1]}`;
  const up = await db.storage.from(BUCKET_COMP).upload(path, bytes, {contentType:`image/${m[1]}`});
  if (up.error) return {error:"No se pudo subir el comprobante: "+up.error.message};
  return {path};
}
async function datosPagoDe(db: any, fechaId?: string) {
  const {data: cfg} = await db.from("config").select("clave,valor").in("clave",["pago_alias","pago_titular","pago_cvu","pago_link"]);
  const g = (k:string) => cfg?.find((c:any)=>c.clave===k)?.valor || "";
  let alias = g("pago_alias"), titular = g("pago_titular"), cvu = g("pago_cvu"), link = g("pago_link");
  if (fechaId) {
    const {data: f} = await db.from("fechas").select("pago_alias,pago_titular").eq("id",fechaId).single();
    if (f?.pago_alias) { alias = f.pago_alias; titular = f.pago_titular || titular; cvu = ""; link = ""; }
  }
  return {alias, titular, cvu, link};
}

async function getDatosPago(db: any, data: any) {
  return {ok:true, ...(await datosPagoDe(db, data.fechaId))};
}

async function enviarComprobanteInscripcion(db: any, data: any) {
  const auth = await requireAuth(db, data);
  if (!auth.ok) return auth;
  const {fechaId, pozoId} = data;
  const [{data: fecha}, {data: partsF}, {data: pozo}] = await Promise.all([
    db.from("fechas").select("*").eq("id",fechaId).single(),
    db.from("partidos").select("fecha_hora").eq("fecha_id",fechaId),
    db.from("pozos").select("*").eq("id",pozoId).eq("fecha_id",fechaId).single(),
  ]);
  if (!fecha || fecha.estado !== "Abierta") return {ok:false, error:"Fecha cerrada"};
  if (!pozo) return {ok:false, error:"Pozo no encontrado"};
  if (minutosHasta(cierreFecha(fecha, partsF||[])) <= 0) return {ok:false, error:"La fecha ya cerró (1 hora antes del primer partido)"};
  const {data: ya} = await db.from("inscripciones").select("*").eq("user_id",auth.userId).eq("pozo_id",pozoId).in("estado_pago",["Pendiente","Aprobado"]).single();
  if (ya?.estado_pago === "Aprobado") return {ok:false, error:"Ya estás inscripto en este pozo"};
  const up = await subirComprobante(db, auth.userId!, data.imagen);
  if (up.error) return {ok:false, error:up.error};
  const ahora = new Date().toISOString();
  if (ya) {
    if (ya.comprobante_path) await db.storage.from(BUCKET_COMP).remove([ya.comprobante_path]);
    await db.from("inscripciones").update({comprobante_path:up.path, comprobante_at:ahora, monto:pozo.monto, rechazo_motivo:null}).eq("id",ya.id);
    return {ok:true, inscripcionId:ya.id};
  }
  const {data: user} = await db.from("usuarios").select("usuario").eq("id",auth.userId).single();
  const id = generarId("INS");
  const {error} = await db.from("inscripciones").insert({
    id, user_id:auth.userId, usuario:user?.usuario, fecha_id:fechaId, pozo_id:pozoId, monto:pozo.monto,
    estado_pago:"Pendiente", habilitado:false, comprobante_path:up.path, comprobante_at:ahora,
  });
  if (error) return {ok:false, error:error.message};
  return {ok:true, inscripcionId:id};
}

async function enviarComprobanteCambio(db: any, data: any) {
  const auth = await requireAuth(db, data);
  if (!auth.ok) return auth;
  const {data: cambio} = await db.from("cambios_pagos").select("*").eq("id",data.cambioId).eq("user_id",auth.userId).single();
  if (!cambio) return {ok:false, error:"Cambio no encontrado"};
  if (cambio.estado !== "Pendiente") return {ok:false, error:"Ese cambio ya no está pendiente"};
  const {data: part} = await db.from("partidos").select("estado,fecha_hora").eq("id",cambio.partido_id).single();
  if (part?.estado === "Finalizado" || (part?.fecha_hora && (new Date(part.fecha_hora).getTime() - Date.now()) / 60000 <= MINUTOS_CIERRE_CAMBIO))
    return {ok:false, error:"Los cambios de este partido ya cerraron (1 hora antes del comienzo)"};
  const up = await subirComprobante(db, auth.userId!, data.imagen);
  if (up.error) return {ok:false, error:up.error};
  if (cambio.comprobante_path) await db.storage.from(BUCKET_COMP).remove([cambio.comprobante_path]);
  await db.from("cambios_pagos").update({comprobante_path:up.path, comprobante_at:new Date().toISOString(), rechazo_motivo:null, estado:"Pagado", mp_status:"revision"}).eq("id",cambio.id);
  const r = await aplicarCambio(db, {...cambio, estado:"Pagado"});
  return {ok:r.ok, mensaje:r.mensaje, error:r.error};
}

async function adminGetPagos(db: any, data: any) {
  const auth = await requireAuth(db, data);
  if (!auth.ok || auth.rol !== "Admin") return {ok:false, error:"Sin permisos"};
  const [{data: insc}, {data: cambios}] = await Promise.all([
    db.from("inscripciones").select("*, usuarios(nombre,usuario,telefono,alias_mp), fechas(nombre), pozos(nombre,monto)").eq("estado_pago","Pendiente").order("comprobante_at",{ascending:true}),
    db.from("cambios_pagos").select("*, usuarios(nombre,usuario,telefono,alias_mp), fechas(nombre)").eq("mp_status","revision").order("comprobante_at",{ascending:true}),
  ]);
  const firmar = async (path: string|null) => path ? (await db.storage.from(BUCKET_COMP).createSignedUrl(path, 3600)).data?.signedUrl || null : null;
  const items: any[] = [];
  for (const i of (insc||[]).filter((x:any) => x.comprobante_path)) items.push({tipo:"insc", id:i.id, usuario:i.usuarios?.usuario, nombre:i.usuarios?.nombre, telefono:i.usuarios?.telefono, alias:i.usuarios?.alias_mp,
    concepto:`Inscripción · ${i.fechas?.nombre||""} · ${i.pozos?.nombre||""}`, monto:i.monto ?? i.pozos?.monto, enviado:i.comprobante_at || i.created_at, comprobante: await firmar(i.comprobante_path)});
  for (const c of (cambios||[])) items.push({tipo:"cambio", id:c.id, usuario:c.usuarios?.usuario, nombre:c.usuarios?.nombre, telefono:c.usuarios?.telefono, alias:c.usuarios?.alias_mp,
    concepto:`Cambio #${c.numero_cambio} · ${c.fechas?.nombre||""} · #${c.numero_partido} ${c.local} vs ${c.visita}: ${c.pronostico_anterior} → ${c.pronostico_nuevo}`, monto:c.monto, enviado:c.comprobante_at, comprobante: await firmar(c.comprobante_path)});
  items.sort((a,b) => String(a.enviado).localeCompare(String(b.enviado)));
  return {ok:true, pagos:items, ...(await datosPagoDe(db))};
}

async function avisar(db: any, userId: string, tipo: string, texto: string) {
  await db.from("avisos").insert({id:generarId("AVI"), user_id:userId, tipo, texto});
}

async function adminResolverPago(db: any, data: any) {
  const auth = await requireAuth(db, data);
  if (!auth.ok || auth.rol !== "Admin") return {ok:false, error:"Sin permisos"};
  const {tipo, id, aprobar} = data;
  const motivo = String(data.motivo || "").slice(0,200) || "No se encontró la transferencia";
  const fmt = (n:any) => "$" + Number(n||0).toLocaleString("es-AR");
  if (tipo === "insc") {
    const {data: i} = await db.from("inscripciones").select("*, fechas(nombre), pozos(nombre,monto)").eq("id",id).single();
    if (!i || i.estado_pago !== "Pendiente") return {ok:false, error:"Esa inscripción ya no está pendiente"};
    if (aprobar) {
      await db.from("inscripciones").update({estado_pago:"Aprobado", habilitado:true, pagado_at:new Date().toISOString(), rechazo_motivo:null}).eq("id",id);
      await avisar(db, i.user_id, "ok", `✅ Pago de ${i.fechas?.nombre||"la fecha"} aprobado (${i.pozos?.nombre||fmt(i.monto)})`);
    } else {
      await db.from("inscripciones").update({estado_pago:"Rechazado", rechazo_motivo:motivo}).eq("id",id);
      // Sin pago no juega: se borran sus pronósticos, reglas y puntos de ese pozo
      await Promise.all([
        db.from("pronosticos").delete().eq("user_id",i.user_id).eq("pozo_id",i.pozo_id),
        db.from("reglas").delete().eq("user_id",i.user_id).eq("pozo_id",i.pozo_id),
        db.from("puntajes").delete().eq("user_id",i.user_id).eq("pozo_id",i.pozo_id),
      ]);
      await avisar(db, i.user_id, "no", `❌ Pago de ${i.fechas?.nombre||"la fecha"} rechazado: ${motivo}. Podés volver a subir el comprobante.`);
    }
    return {ok:true};
  }
  if (tipo === "cambio") {
    const {data: c} = await db.from("cambios_pagos").select("*, fechas(nombre)").eq("id",id).single();
    if (!c || c.mp_status !== "revision") return {ok:false, error:"Ese cambio ya no está en revisión"};
    if (aprobar) {
      await db.from("cambios_pagos").update({mp_status:"transferencia_ok"}).eq("id",id);
      await avisar(db, c.user_id, "ok", `✅ Pago del cambio #${c.numero_partido} ${c.local} vs ${c.visita} aprobado (${fmt(c.monto)})`);
      return {ok:true};
    }
    // Rechazado: se deshace el cambio y vuelve el pronóstico anterior
    const {data: pr} = await db.from("pronosticos").select("*").eq("user_id",c.user_id).eq("partido_id",c.partido_id).eq("pozo_id",c.pozo_id).single();
    if (pr) await db.from("pronosticos").update({pronostico:c.pronostico_anterior, cambios_realizados:Math.max(0,(pr.cambios_realizados||1)-1), updated_at:new Date().toISOString()}).eq("id",pr.id);
    await db.from("cambios_pagos").update({estado:"Cancelado", mp_status:"rechazado", rechazo_motivo:motivo}).eq("id",id);
    const {data: part} = await db.from("partidos").select("estado").eq("id",c.partido_id).single();
    if (part?.estado === "Finalizado") await calcularPuntajesPartido(db, c.partido_id);
    await avisar(db, c.user_id, "no", `❌ Pago del cambio #${c.numero_partido} rechazado: ${motivo}. Tu pronóstico volvió a ${c.pronostico_anterior}.`);
    return {ok:true};
  }
  return {ok:false, error:"Tipo inválido"};
}

async function getAvisos(db: any, data: any) {
  const auth = await requireAuth(db, data);
  if (!auth.ok) return auth;
  const {data: av} = await db.from("avisos").select("id,tipo,texto,created_at").eq("user_id",auth.userId).eq("visto",false).order("created_at");
  if (av?.length) await db.from("avisos").update({visto:true}).in("id", av.map((x:any) => x.id));
  return {ok:true, avisos:av||[]};
}

async function adminGuardarDatosPago(db: any, data: any) {
  const auth = await requireAuth(db, data);
  if (!auth.ok || auth.rol !== "Admin") return {ok:false, error:"Sin permisos"};
  const alias = String(data.alias||"").trim().slice(0,60), titular = String(data.titular||"").trim().slice(0,80);
  const cvu = String(data.cvu||"").replace(/\D/g,"").slice(0,22);
  const link = /^https:\/\/(mpago\.la|link\.mercadopago\.com\.ar|www\.mercadopago\.com\.ar)\//.test(String(data.link||"")) ? String(data.link).trim() : "";
  await db.from("config").upsert([{clave:"pago_alias", valor:alias},{clave:"pago_titular", valor:titular},{clave:"pago_cvu", valor:cvu},{clave:"pago_link", valor:link}], {onConflict:"clave"});
  return {ok:true};
}

// ============================================================
//  EMPRESAS
//  Cada empresa tiene su código, su marca (logo, eslogan, colores) y sus fechas.
//  Rol "AdminEmpresa": escribe novedades/premios y cambia la marca de SU empresa.
//  Los empleados juegan gratis (paga la empresa) y solo ven las fechas de su empresa.
// ============================================================
const TEMAS_EMPRESA = ["cancha","copa","pasion","marca"];
function empresaOut(e: any) {
  if (!e) return null;
  return {id:e.id, nombre:e.nombre, codigo:e.codigo, slogan:e.slogan||"", logo:e.logo_url||"", color:e.color||"#2F6BFF", tema:e.tema||"marca", campos:Array.isArray(e.campos)?e.campos:[]};
}
async function empresaPorCodigo(db: any, codigo: any) {
  const c = normalizarCodigo(codigo);
  if (!c) return null;
  const {data} = await db.from("empresas").select("*").eq("codigo", c).eq("estado","Activa").maybeSingle();
  return data || null;
}
async function userOut(db: any, user: any) {
  let empresa = null;
  if (user.empresa_id) { const {data} = await db.from("empresas").select("*").eq("id", user.empresa_id).maybeSingle(); empresa = empresaOut(data); }
  return {id:user.id, usuario:user.usuario, nombre:user.nombre, alias:user.alias_mp, email:user.email, telefono:user.telefono,
    avatar:user.avatar, fotoPendiente:user.foto_pendiente||null, rol:user.rol, cupones:user.cupones, empresa, datosExtra:user.datos_extra||{}};
}

// Pública: para mostrar la marca en la pantalla de ingreso cuando entran con el link de la empresa
async function getEmpresaPublica(db: any, data: any) {
  const e = await empresaPorCodigo(db, data.codigo);
  if (!e) return {ok:false, error:"El código de empresa no existe"};
  return {ok:true, empresa: empresaOut(e)};
}

// Empleado: entrar a jugar una fecha de su empresa (gratis, sin comprobante)
async function jugarEmpresa(db: any, data: any) {
  const auth = await requireAuth(db, data);
  if (!auth.ok) return auth;
  const {data: fecha} = await db.from("fechas").select("*").eq("id", data.fechaId).single();
  if (!fecha || !fecha.empresa_id || fecha.empresa_id !== auth.empresaId) return {ok:false, error:"Esta fecha no es de tu empresa"};
  const {data: pozos} = await db.from("pozos").select("id").eq("fecha_id", fecha.id).eq("estado","Activo").order("monto");
  const pozo = pozos?.[0];
  if (!pozo) return {ok:false, error:"La fecha todavía no está lista"};
  const {data: ya} = await db.from("inscripciones").select("id").eq("user_id",auth.userId).eq("pozo_id",pozo.id).in("estado_pago",["Pendiente","Aprobado"]).maybeSingle();
  if (ya) return {ok:true, fechaId:fecha.id, pozoId:pozo.id};
  if (fecha.estado !== "Abierta") return {ok:false, error:"Esta fecha ya está cerrada"};
  const {data: partsF} = await db.from("partidos").select("fecha_hora").eq("fecha_id", fecha.id);
  if (minutosHasta(cierreFecha(fecha, partsF||[])) <= 0) return {ok:false, error:"La fecha ya cerró (1 hora antes del primer partido)"};
  const {data: user} = await db.from("usuarios").select("usuario").eq("id",auth.userId).single();
  const {error} = await db.from("inscripciones").insert({
    id:generarId("INS"), user_id:auth.userId, usuario:user?.usuario, fecha_id:fecha.id, pozo_id:pozo.id,
    estado_pago:"Aprobado", habilitado:true, pagado_at:new Date().toISOString(), via_codigo:true,
  });
  if (error) return {ok:false, error:error.message};
  return {ok:true, fechaId:fecha.id, pozoId:pozo.id};
}

// Novedades y premios de la empresa
async function getNovedades(db: any, data: any) {
  const auth = await requireAuth(db, data);
  if (!auth.ok) return auth;
  const empresaId = auth.rol === "Admin" ? (data.empresaId || auth.empresaId) : auth.empresaId;
  if (!empresaId) return {ok:true, novedades:[]};
  const {data: n} = await db.from("novedades").select("*").eq("empresa_id", empresaId).order("created_at", {ascending:false}).limit(50);
  return {ok:true, novedades:(n||[]).map((x:any) => ({id:x.id, tipo:x.tipo, titulo:x.titulo, texto:x.texto, autor:x.autor, fecha:x.created_at}))};
}
// Quién puede tocar la empresa: el admin general (cualquiera) o el admin de esa empresa
function empresaEditable(auth: any, empresaId: string) {
  return auth.ok && (auth.rol === "Admin" || (auth.rol === "AdminEmpresa" && auth.empresaId === empresaId));
}
async function guardarNovedad(db: any, data: any) {
  const auth = await requireAuth(db, data);
  const empresaId = auth.rol === "Admin" ? data.empresaId : auth.empresaId;
  if (!empresaId || !empresaEditable(auth, empresaId)) return {ok:false, error:"Sin permisos"};
  const titulo = String(data.titulo||"").trim();
  if (!titulo) return {ok:false, error:"Escribí un título"};
  const {data: u} = await db.from("usuarios").select("usuario").eq("id", auth.userId).single();
  const fila = {empresa_id:empresaId, tipo:data.tipo === "premio" ? "premio" : "novedad", titulo:titulo.slice(0,120), texto:String(data.texto||"").trim().slice(0,1500), autor:u?.usuario||""};
  const {error} = data.id
    ? await db.from("novedades").update(fila).eq("id", data.id).eq("empresa_id", empresaId)
    : await db.from("novedades").insert({id:generarId("NOV"), ...fila});
  if (error) return {ok:false, error:error.message};
  return {ok:true};
}
async function borrarNovedad(db: any, data: any) {
  const auth = await requireAuth(db, data);
  const {data: n} = await db.from("novedades").select("empresa_id").eq("id", data.id).maybeSingle();
  if (!n || !empresaEditable(auth, n.empresa_id)) return {ok:false, error:"Sin permisos"};
  await db.from("novedades").delete().eq("id", data.id);
  return {ok:true};
}

// Logo: data URL (png/jpg/webp/svg) → bucket público, devuelve la URL
async function subirLogoEmpresa(db: any, empresaId: string, imagen: string) {
  const m = /^data:image\/(jpeg|png|webp|svg\+xml);base64,(.+)$/.exec(String(imagen||""));
  if (!m) return {ok:false, error:"Logo inválido"};
  const bytes = Uint8Array.from(atob(m[2]), c => c.charCodeAt(0));
  if (bytes.length > 600*1024) return {ok:false, error:"El logo es muy pesado (máximo 600 KB)"};
  await asegurarBucket(db);
  const ext = m[1] === "jpeg" ? "jpg" : m[1] === "svg+xml" ? "svg" : m[1];
  const ruta = `empresas/${empresaId}-${Date.now()}.${ext}`;
  const up = await db.storage.from(BUCKET).upload(ruta, bytes, {contentType:`image/${m[1]}`, upsert:true});
  if (up.error) return {ok:false, error:"No se pudo subir el logo: "+up.error.message};
  return {ok:true, url: db.storage.from(BUCKET).getPublicUrl(ruta).data.publicUrl};
}
// Campos de marca que pueden cambiar tanto el admin general como el de la empresa
async function camposMarca(db: any, empresaId: string, data: any) {
  const upd: any = {};
  if (data.nombre !== undefined) { const n = String(data.nombre||"").trim(); if (n.length < 2) return {error:"Poné el nombre de la empresa"}; upd.nombre = n.slice(0,40); }
  if (data.slogan !== undefined) upd.slogan = String(data.slogan||"").trim().slice(0,80);
  if (data.tema !== undefined) { if (!TEMAS_EMPRESA.includes(data.tema)) return {error:"Tema inválido"}; upd.tema = data.tema; }
  if (data.color !== undefined) { if (!/^#[0-9a-fA-F]{6}$/.test(String(data.color))) return {error:"Color inválido"}; upd.color = String(data.color).toUpperCase(); }
  if (data.logo) { const r: any = await subirLogoEmpresa(db, empresaId, data.logo); if (!r.ok) return {error:r.error}; upd.logo_url = r.url; }
  if (data.quitarLogo) upd.logo_url = null;
  if (data.campos !== undefined) { const c = limpiarCampos(data.campos); if (c.error) return {error:c.error}; upd.campos = c.campos; }
  return {upd};
}
async function guardarMarcaEmpresa(db: any, data: any) {
  const auth = await requireAuth(db, data);
  const empresaId = auth.rol === "Admin" ? data.empresaId : auth.empresaId;
  if (!empresaId || !empresaEditable(auth, empresaId)) return {ok:false, error:"Sin permisos"};
  const c: any = await camposMarca(db, empresaId, data);
  if (c.error) return {ok:false, error:c.error};
  if (Object.keys(c.upd).length) await db.from("empresas").update(c.upd).eq("id", empresaId);
  const {data: e} = await db.from("empresas").select("*").eq("id", empresaId).single();
  return {ok:true, empresa: empresaOut(e)};
}

// Admin general: listar, crear y editar empresas
async function adminGetEmpresas(db: any, data: any) {
  const auth = await requireAuth(db, data);
  if (!auth.ok || auth.rol !== "Admin") return {ok:false, error:"Sin permisos"};
  const [{data: emps}, {data: users}] = await Promise.all([
    db.from("empresas").select("*").order("created_at"),
    db.from("usuarios").select("id,usuario,nombre,telefono,email,rol,empresa_id,datos_extra").not("empresa_id","is",null),
  ]);
  const {data: invs} = await db.from("empresa_invitaciones").select("*").order("created_at");
  return {ok:true, empresas:(emps||[]).map((e:any) => ({...empresaOut(e), estado:e.estado,
    usuarios:(users||[]).filter((u:any) => u.empresa_id === e.id).map((u:any) => ({id:u.id, usuario:u.usuario, nombre:u.nombre, telefono:u.telefono, email:u.email||"", rol:u.rol, datos:u.datos_extra||{}})),
    invitaciones:(invs||[]).filter((i:any) => i.empresa_id === e.id).map((i:any) => ({id:i.id, email:i.email}))}))};
}
async function adminGuardarEmpresa(db: any, data: any) {
  const auth = await requireAuth(db, data);
  if (!auth.ok || auth.rol !== "Admin") return {ok:false, error:"Sin permisos"};
  let id = data.id;
  if (!id) {
    const codigo = normalizarCodigo(data.codigo);
    if (!codigo || codigo.length < 3) return {ok:false, error:"El código tiene que tener al menos 3 letras o números"};
    if (!String(data.nombre||"").trim()) return {ok:false, error:"Poné el nombre de la empresa"};
    id = generarId("EMP");
    const {error} = await db.from("empresas").insert({id, nombre:String(data.nombre).trim().slice(0,40), codigo});
    if (error) return {ok:false, error: error.code === "23505" ? "Ese código ya lo usa otra empresa" : error.message};
  } else if (data.codigo !== undefined) {
    const codigo = normalizarCodigo(data.codigo);
    if (!codigo || codigo.length < 3) return {ok:false, error:"El código tiene que tener al menos 3 letras o números"};
    const {error} = await db.from("empresas").update({codigo}).eq("id", id);
    if (error) return {ok:false, error: error.code === "23505" ? "Ese código ya lo usa otra empresa" : error.message};
  }
  if (data.estado) await db.from("empresas").update({estado: data.estado === "Pausada" ? "Pausada" : "Activa"}).eq("id", id);
  const c: any = await camposMarca(db, id, data);
  if (c.error) return {ok:false, error:c.error};
  if (Object.keys(c.upd).length) await db.from("empresas").update(c.upd).eq("id", id);
  const {data: e} = await db.from("empresas").select("*").eq("id", id).single();
  return {ok:true, empresa: empresaOut(e)};
}
// Admin general: hacer (o sacar) admin de su empresa a un empleado
async function adminSetRol(db: any, data: any) {
  const auth = await requireAuth(db, data);
  if (!auth.ok || auth.rol !== "Admin") return {ok:false, error:"Sin permisos"};
  if (!["Jugador","AdminEmpresa"].includes(data.rol)) return {ok:false, error:"Rol inválido"};
  const {data: u} = await db.from("usuarios").select("empresa_id,rol").eq("id", data.userId).single();
  if (!u?.empresa_id) return {ok:false, error:"Ese usuario no es de ninguna empresa"};
  if (u.rol === "Admin") return {ok:false, error:"No se puede cambiar al administrador general"};
  await db.from("usuarios").update({rol:data.rol}).eq("id", data.userId);
  return {ok:true};
}

// ============================================================
//  FECHAS: ocultar, eliminar, copiar a empresas
// ============================================================
// El mismo partido copiado en varias fechas (mismo id de la API, o mismos equipos y horario)
async function partidosGemelos(db: any, partidoId: string): Promise<string[]> {
  const {data: p} = await db.from("partidos").select("id,partido_api_id,local,visita,fecha_hora").eq("id", partidoId).single();
  if (!p) return [partidoId];
  const q = p.partido_api_id
    ? db.from("partidos").select("id").eq("partido_api_id", p.partido_api_id)
    : db.from("partidos").select("id").eq("local", p.local).eq("visita", p.visita).eq("fecha_hora", p.fecha_hora);
  const {data} = await q;
  const ids = (data||[]).map((x:any) => x.id);
  return ids.includes(partidoId) ? [partidoId, ...ids.filter((i:string) => i !== partidoId)] : [partidoId, ...ids];
}
async function adminOcultarFecha(db: any, data: any) {
  const auth = await requireAuth(db, data);
  if (!auth.ok || auth.rol !== "Admin") return {ok:false, error:"Sin permisos"};
  await db.from("fechas").update({oculta: !!data.oculta}).eq("id", data.fechaId);
  return {ok:true};
}
async function adminEliminarFecha(db: any, data: any) {
  const auth = await requireAuth(db, data);
  if (!auth.ok || auth.rol !== "Admin") return {ok:false, error:"Sin permisos"};
  const id = data.fechaId;
  const {data: f} = await db.from("fechas").select("id,estado").eq("id", id).single();
  if (!f) return {ok:false, error:"Fecha no encontrada"};
  const {count} = await db.from("inscripciones").select("id", {count:"exact", head:true}).eq("fecha_id", id);
  if (f.estado === "Abierta" && (count||0) > 0) return {ok:false, error:"Tiene jugadores anotados y sigue abierta: cerrala primero"};
  // Borrar todo lo que cuelga de la fecha (en orden, por las referencias)
  for (const t of ["cambios_pagos","puntajes","reglas","pronosticos","ganadores","grupos","inscripciones"]) {
    const {error} = await db.from(t).delete().eq("fecha_id", id);
    if (error && !/does not exist|column/.test(error.message)) return {ok:false, error:`No se pudo borrar (${t}): ${error.message}`};
  }
  const {error} = await db.from("fechas").delete().eq("id", id); // pozos y partidos se van solos
  if (error) return {ok:false, error:error.message};
  return {ok:true};
}
// Copia la fecha (partidos y tipos, sin resultados ni pronósticos) a una o varias empresas, o como pública ("")
async function adminCopiarFecha(db: any, data: any) {
  const auth = await requireAuth(db, data);
  if (!auth.ok || auth.rol !== "Admin") return {ok:false, error:"Sin permisos"};
  const destinos: string[] = Array.isArray(data.destinos) ? data.destinos : [];
  if (!destinos.length) return {ok:false, error:"Elegí al menos un destino"};
  const [{data: f}, {data: parts}, {data: emps}] = await Promise.all([
    db.from("fechas").select("*").eq("id", data.fechaId).single(),
    db.from("partidos").select("*").eq("fecha_id", data.fechaId).order("numero"),
    db.from("empresas").select("id,nombre"),
  ]);
  if (!f) return {ok:false, error:"Fecha no encontrada"};
  const creadas: string[] = [];
  for (const dest of destinos) {
    const emp = dest ? (emps||[]).find((e:any) => e.id === dest) : null;
    if (dest && !emp) continue;
    const id = generarId("FECHA");
    const {error} = await db.from("fechas").insert({
      id, nombre: String(data.nombre||f.nombre).slice(0,80), descripcion:f.descripcion||"", liga:f.liga||"",
      plazo_limite:f.plazo_limite, reglas_habilitadas:f.reglas_habilitadas||[], cant_partidos:(parts||[]).length,
      estado:"Abierta", empresa_id: emp ? emp.id : null,
    });
    if (error) return {ok:false, error:error.message};
    if ((parts||[]).length) await db.from("partidos").insert((parts||[]).map((p:any) => ({
      id:generarId("PAR"), fecha_id:id, numero:p.numero, local:p.local, visita:p.visita, local_logo:p.local_logo, visita_logo:p.visita_logo,
      fecha_hora:p.fecha_hora, liga:p.liga, liga_id:p.liga_id, partido_api_id:p.partido_api_id, tipo:p.tipo, estado:"Pendiente", tarjetas_rojas:0,
    })));
    if (emp) await db.from("pozos").insert({id:generarId("POZ"), fecha_id:id, nombre:`Polla ${emp.nombre}`, monto:0, comision_pct:0, premio_fijo:0});
    creadas.push(id);
  }
  return {ok:true, creadas: creadas.length};
}

// ── Preguntas propias de la empresa ──────────────────────────
// campos: [{id, label, tipo:"texto"|"opciones", opciones:[...], obligatorio}]
function limpiarCampos(campos: any) {
  if (!Array.isArray(campos)) return {error:"Preguntas inválidas"};
  if (campos.length > 10) return {error:"Máximo 10 preguntas"};
  const out: any[] = [];
  for (const c of campos) {
    const label = String(c?.label||"").trim().slice(0,60);
    if (!label) return {error:"Hay una pregunta sin texto"};
    const tipo = c.tipo === "opciones" ? "opciones" : "texto";
    const opciones = tipo === "opciones" ? (Array.isArray(c.opciones)?c.opciones:[]).map((o:any) => String(o||"").trim().slice(0,40)).filter(Boolean).slice(0,30) : [];
    if (tipo === "opciones" && opciones.length < 2) return {error:`"${label}": poné al menos 2 opciones`};
    out.push({id: String(c.id || ("c"+crypto.randomUUID().slice(0,8))).slice(0,20), label, tipo, opciones, obligatorio: !!c.obligatorio});
  }
  return {campos: out};
}
function validarDatosEmpresa(empresa: any, datos: any) {
  const campos = Array.isArray(empresa?.campos) ? empresa.campos : [];
  const out: any = {};
  for (const c of campos) {
    let v = String(datos?.[c.id] ?? "").trim().slice(0,80);
    if (c.tipo === "opciones" && v && !c.opciones.includes(v)) v = "";
    if (c.obligatorio && !v) return {error:`Completá: ${c.label}`};
    if (v) out[c.id] = v;
  }
  return {datos: out};
}
// El empleado completa/actualiza sus respuestas (desde el Perfil o cuando se agregan preguntas nuevas)
async function guardarMisDatosEmpresa(db: any, data: any) {
  const auth = await requireAuth(db, data);
  if (!auth.ok) return auth;
  if (!auth.empresaId) return {ok:false, error:"Tu cuenta no es de ninguna empresa"};
  const {data: e} = await db.from("empresas").select("*").eq("id", auth.empresaId).single();
  const v = validarDatosEmpresa(e, data.datos || {});
  if (v.error) return {ok:false, error:v.error};
  await db.from("usuarios").update({datos_extra: v.datos}).eq("id", auth.userId);
  return {ok:true, datosExtra: v.datos};
}
// Admin de la empresa: ver a su gente (con sus respuestas)
async function empresaGetEmpleados(db: any, data: any) {
  const auth = await requireAuth(db, data);
  const empresaId = auth.rol === "Admin" ? data.empresaId : auth.empresaId;
  if (!empresaId || !empresaEditable(auth, empresaId)) return {ok:false, error:"Sin permisos"};
  const {data: us} = await db.from("usuarios").select("id,usuario,nombre,email,rol,datos_extra,created_at").eq("empresa_id", empresaId).order("created_at");
  return {ok:true, empleados:(us||[]).map((u:any) => ({id:u.id, usuario:u.usuario, nombre:u.nombre, email:u.email||"", rol:u.rol, datos:u.datos_extra||{}}))};
}

// ── Admins de empresa por correo ──────────────────────────────
async function adminInvitarAdmin(db: any, data: any) {
  const auth = await requireAuth(db, data);
  if (!auth.ok || auth.rol !== "Admin") return {ok:false, error:"Sin permisos"};
  const email = String(data.email||"").trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return {ok:false, error:"Ese correo no parece válido"};
  const {data: emp} = await db.from("empresas").select("*").eq("id", data.empresaId).single();
  if (!emp) return {ok:false, error:"Empresa no encontrada"};
  const {data: us} = await db.from("usuarios").select("id,nombre,usuario,rol,empresa_id").ilike("email", email);
  const u = (us||[])[0];
  if (u) {
    if (u.rol === "Admin") return {ok:false, error:"Ese correo es del administrador general"};
    if (u.empresa_id && u.empresa_id !== emp.id) return {ok:false, error:`${u.nombre||u.usuario} ya pertenece a otra empresa`};
    await db.from("usuarios").update({empresa_id: emp.id, rol:"AdminEmpresa", alias_mp:""}).eq("id", u.id);
    return {ok:true, estado:"asignado", nombre: u.nombre || u.usuario};
  }
  const {error} = await db.from("empresa_invitaciones").upsert({id:generarId("INV"), empresa_id:emp.id, email}, {onConflict:"empresa_id,email", ignoreDuplicates:true});
  if (error) return {ok:false, error:error.message};
  const APP_URL = Deno.env.get("APP_URL") || "https://gr10-cdu.github.io/PollaProdes/";
  const link = `${APP_URL.replace(/\/?$/,"/")}${encodeURIComponent(String(emp.codigo).toLowerCase())}`;
  const m = await enviarMail(email, `Sos administrador de la Polla de ${emp.nombre}`,
    `<div style="font-family:Arial,sans-serif;max-width:520px;margin:auto;padding:24px"><h2>¡Hola!</h2><p>Te sumaron como <b>administrador de la Polla de ${esc(emp.nombre)}</b>.</p><p>Registrate con este correo (<b>${esc(email)}</b>) y vas a poder publicar novedades y premios para tu gente.</p><p><a href="${link}" style="display:inline-block;background:#0FA958;color:#fff;padding:12px 20px;border-radius:10px;text-decoration:none;font-weight:bold">Entrar a la Polla</a></p></div>`);
  return {ok:true, estado:"invitado", link, mailEnviado: !!m.ok};
}
async function adminQuitarInvitacion(db: any, data: any) {
  const auth = await requireAuth(db, data);
  if (!auth.ok || auth.rol !== "Admin") return {ok:false, error:"Sin permisos"};
  await db.from("empresa_invitaciones").delete().eq("id", data.id);
  return {ok:true};
}

// ============================================================
//  PARTIDOS CARGADOS A MANO (sin la API)
// ============================================================
// Escudo: si la API anda, se busca el equipo por nombre; si no, queda sin escudo
async function buscarEquipos(db: any, data: any) {
  const auth = await requireAuth(db, data);
  if (!auth.ok || auth.rol !== "Admin") return {ok:false, error:"Sin permisos"};
  const q = String(data.q||"").trim();
  if (q.length < 3) return {ok:true, equipos:[]};
  try {
    const r = await callAPIFootball("teams", {search:q});
    if (errorAPIFootball(r)) return {ok:true, equipos:[], sinApi:true};
    return {ok:true, equipos:(r.response||[]).slice(0,8).map((t:any) => ({nombre:t.team?.name, logo:t.team?.logo, pais:t.team?.country}))};
  } catch { return {ok:true, equipos:[], sinApi:true}; }
}
async function escudoDe(nombre: string): Promise<string> {
  try {
    const r = await callAPIFootball("teams", {search:nombre});
    if (errorAPIFootball(r)) return "";
    const lista = r.response||[], n = nombre.toLowerCase();
    const t = lista.find((x:any) => String(x.team?.name||"").toLowerCase() === n) || lista[0];
    return t?.team?.logo || "";
  } catch { return ""; }
}
async function renumerarPartidos(db: any, fechaId: string) {
  const {data: ps} = await db.from("partidos").select("id,numero,fecha_hora").eq("fecha_id", fechaId).order("fecha_hora").order("numero");
  let i = 0;
  for (const p of (ps||[])) { i++; if (p.numero !== i) await db.from("partidos").update({numero:i}).eq("id", p.id); }
  await db.from("fechas").update({cant_partidos:i}).eq("id", fechaId);
}
function datosPartidoManual(data: any) {
  const local = String(data.local||"").trim().slice(0,40), visita = String(data.visita||"").trim().slice(0,40);
  if (!local || !visita) return {error:"Poné los dos equipos"};
  const fh = new Date(data.fechaHora);
  if (isNaN(fh.getTime())) return {error:"Fecha y hora inválidas"};
  const tipo = ["Normal","Doble","Polla"].includes(data.tipo) ? data.tipo : "Normal";
  return {local, visita, fecha_hora: fh.toISOString(), tipo};
}
async function adminAgregarPartido(db: any, data: any) {
  const auth = await requireAuth(db, data);
  if (!auth.ok || auth.rol !== "Admin") return {ok:false, error:"Sin permisos"};
  const d: any = datosPartidoManual(data);
  if (d.error) return {ok:false, error:d.error};
  const {data: f} = await db.from("fechas").select("id,liga,cant_partidos").eq("id", data.fechaId).single();
  if (!f) return {ok:false, error:"Fecha no encontrada"};
  if ((f.cant_partidos||0) >= 30) return {ok:false, error:"Máximo 30 partidos por fecha"};
  if (d.tipo === "Polla") await db.from("partidos").update({tipo:"Normal"}).eq("fecha_id", f.id).eq("tipo","Polla"); // una sola Polla
  const [ll, lv] = await Promise.all([data.localLogo ? data.localLogo : escudoDe(d.local), data.visitaLogo ? data.visitaLogo : escudoDe(d.visita)]);
  const id = generarId("PAR");
  const {error} = await db.from("partidos").insert({id, fecha_id:f.id, numero:(f.cant_partidos||0)+1, ...d, liga:data.liga||f.liga||"",
    local_logo:String(ll||""), visita_logo:String(lv||""), estado:"Pendiente", tarjetas_rojas:0});
  if (error) return {ok:false, error:error.message};
  await renumerarPartidos(db, f.id);
  return {ok:true, partidoId:id, conEscudo: !!(ll && lv)};
}
async function adminEditarPartido(db: any, data: any) {
  const auth = await requireAuth(db, data);
  if (!auth.ok || auth.rol !== "Admin") return {ok:false, error:"Sin permisos"};
  const {data: p} = await db.from("partidos").select("*").eq("id", data.partidoId).single();
  if (!p) return {ok:false, error:"Partido no encontrado"};
  const d: any = datosPartidoManual(data);
  if (d.error) return {ok:false, error:d.error};
  if (d.tipo === "Polla") await db.from("partidos").update({tipo:"Normal"}).eq("fecha_id", p.fecha_id).eq("tipo","Polla").neq("id", p.id);
  const upd: any = {...d};
  if (d.local !== p.local) upd.local_logo = data.localLogo || await escudoDe(d.local);
  if (d.visita !== p.visita) upd.visita_logo = data.visitaLogo || await escudoDe(d.visita);
  await db.from("partidos").update(upd).eq("id", p.id);
  await renumerarPartidos(db, p.fecha_id);
  return {ok:true};
}
async function adminBorrarPartido(db: any, data: any) {
  const auth = await requireAuth(db, data);
  if (!auth.ok || auth.rol !== "Admin") return {ok:false, error:"Sin permisos"};
  const {data: p} = await db.from("partidos").select("id,fecha_id,estado").eq("id", data.partidoId).single();
  if (!p) return {ok:false, error:"Partido no encontrado"};
  if (p.estado === "Finalizado") return {ok:false, error:"Ya tiene resultado: no se puede borrar"};
  await db.from("cambios_pagos").delete().eq("partido_id", p.id);
  const {error} = await db.from("partidos").delete().eq("id", p.id); // pronósticos, reglas y puntajes se van solos
  if (error) return {ok:false, error:error.message};
  await renumerarPartidos(db, p.fecha_id);
  return {ok:true};
}
