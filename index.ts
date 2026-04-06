// ============================================================
//  POLLA PRODES — Edge Function principal
//  Supabase Edge Functions (Deno)
//  2026-04-05 ARG
// ============================================================

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SUPABASE_SERVICE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const API_SECRET = Deno.env.get("API_SECRET") || "PP2026-xK9mQ7vL2nR4wT8yU3pA5cE1hG6jF0bD";

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
const MAX_CAMBIOS = 3, MINUTOS_CIERRE = 30;

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

async function requireAuth(db: any, data: any): Promise<{ok:boolean, userId?:string, rol?:string, error?:string}> {
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
  const { data: user } = await db.from("usuarios").select("rol").eq("id", sesion.user_id).single();
  return {ok:true, userId: sesion.user_id, rol: user?.rol || "Jugador"};
}

// ── ROUTER ──────────────────────────────────────────────────
Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, {headers: corsHeaders()});
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
      case "getFecha": return resp(await getFecha(db, data));

      // ── POZOS E INSCRIPCIONES ─────────────────────────────
      case "getPozos": return resp(await getPozos(db, data));
      case "inscribirse": return resp(await inscribirse(db, data));
      case "getMisInscripciones": return resp(await getMisInscripciones(db, data));
      case "crearPreferencia": return resp(await crearPreferencia(db, data));

      // ── PRONÓSTICOS ───────────────────────────────────────
      case "autoguardar": return resp(await autoguardar(db, data));
      case "getMiFecha": return resp(await getMiFecha(db, data));
      case "guardarReglas": return resp(await guardarReglas(db, data));

      // ── PUNTAJES ──────────────────────────────────────────
      case "getTabla": return resp(await getTabla(db, data));
      case "getNoticias": return resp(await getNoticias(db));

      // ── ADMIN ─────────────────────────────────────────────
      case "adminCrearFecha": return resp(await adminCrearFecha(db, data));
      case "adminEditarFecha": return resp(await adminEditarFecha(db, data));
      case "adminCerrarFecha": return resp(await adminCerrarFecha(db, data));
      case "adminCrearPozo": return resp(await adminCrearPozo(db, data));
      case "adminIngresarResultado": return resp(await adminIngresarResultado(db, data));
      case "adminGetUsuarios": return resp(await adminGetUsuarios(db, data));
      case "agregarNoticia": return resp(await agregarNoticia(db, data));
      case "eliminarNoticia": return resp(await eliminarNoticia(db, data));
      case "importarPartidos": return resp(await importarPartidos(db, data));
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
  const pinHash = await hashPinAsync(pin);

  // Verificar si existe
  const {data: existe} = await db.from("usuarios").select("id").eq("telefono", tel).single();
  if (existe) return {ok:false, error:"Teléfono ya registrado"};

  const usuario = generarUsuario(nombre, tel);
  const id = generarId("USR");

  const {error} = await db.from("usuarios").insert({
    id, telefono: tel, pin_hash: pinHash, usuario, nombre,
    alias_mp: data.alias || "", email: data.email || "",
  });
  if (error) return {ok:false, error: error.message};

  const token = await crearSesion(db, id);
  return {ok:true, user:{id, usuario, nombre, rol:"Jugador"}, sessionToken: token};
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

  const pinHash = await hashPinAsync(data.pin);
  if (user.pin_hash !== pinHash) return {ok:false, error:"PIN incorrecto"};

  await db.from("usuarios").update({ultimo_login: new Date().toISOString()}).eq("id", user.id);
  const token = await crearSesion(db, user.id);
  return {ok:true, user:{id:user.id, usuario:user.usuario, nombre:user.nombre, alias:user.alias_mp, email:user.email, avatar:user.avatar, rol:user.rol, cupones:user.cupones}, sessionToken: token};
}

// ============================================================
//  LOGIN CON TOKEN
// ============================================================
async function loginConToken(db: any, data: any) {
  const auth = await requireAuth(db, data);
  if (!auth.ok) return auth;
  const {data: user} = await db.from("usuarios").select("*").eq("id", auth.userId).single();
  if (!user) return {ok:false, error:"Usuario no encontrado"};
  return {ok:true, user:{id:user.id, usuario:user.usuario, nombre:user.nombre, alias:user.alias_mp, email:user.email, avatar:user.avatar, rol:user.rol, cupones:user.cupones}, sessionToken: data.sessionToken};
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
  const {data: fechas} = await db.from("fechas")
    .select("*")
    .in("estado", ["Abierta","Cerrada","Jugada"])
    .order("plazo_limite");

  const ahora = new Date();
  return {ok:true, fechas: (fechas||[]).map((f:any) => {
    const plazo = new Date(f.plazo_limite);
    const mins = Math.floor((plazo.getTime() - ahora.getTime()) / 60000);
    return {
      id: f.id, nombre: f.nombre, descripcion: f.descripcion,
      plazoLimite: f.plazo_limite, estado: f.estado,
      cantPartidos: f.cant_partidos, liga: f.liga,
      reglasHabilitadas: f.reglas_habilitadas || [],
      puedeJugar: f.estado === "Abierta" && mins > MINUTOS_CIERRE,
      minutosRestantes: mins,
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
  const mins = Math.floor((new Date(fecha.plazo_limite).getTime() - ahora.getTime()) / 60000);
  const reglasDetalle = (fecha.reglas_habilitadas||[]).filter((c:string) => REGLAS_DEF[c]).map((c:string) => ({
    codigo:c, ...REGLAS_DEF[c]
  }));

  return {ok:true,
    fecha: {id:fecha.id, nombre:fecha.nombre, descripcion:fecha.descripcion, plazoLimite:fecha.plazo_limite, estado:fecha.estado, cantPartidos:fecha.cant_partidos, liga:fecha.liga, puedeJugar:fecha.estado==="Abierta"&&mins>MINUTOS_CIERRE, minutosRestantes:mins, reglasHabilitadas:fecha.reglas_habilitadas||[], reglasDetalle},
    partidos: (parts||[]).map((p:any) => ({
      id:p.id, numero:p.numero, local:p.local, visita:p.visita,
      fechaHora:p.fecha_hora, liga:p.liga, tipo:p.tipo, estado:p.estado,
      golesLocal:p.goles_local, golesVisita:p.goles_visita,
      resultado:p.resultado, tarjetasRojas:p.tarjetas_rojas||0,
      localLogo:p.local_logo||"", visitaLogo:p.visita_logo||"",
    })),
  };
}

// ============================================================
//  GET POZOS
// ============================================================
async function getPozos(db: any, data: any) {
  if (!data.fechaId) return {ok:false, error:"Falta fechaId"};

  const [{data: pozos}, {data: inscripciones}] = await Promise.all([
    db.from("pozos").select("*").eq("fecha_id", data.fechaId).eq("estado","Activo").order("monto"),
    db.from("inscripciones").select("*").eq("fecha_id", data.fechaId).in("estado_pago",["Pendiente","Aprobado"]),
  ]);

  const {data: parts} = await db.from("partidos").select("id").eq("fecha_id", data.fechaId);
  const cantPartidos = parts?.length || 0;

  return {ok:true, pozos: (pozos||[]).map((p:any) => {
    const insc = (inscripciones||[]).filter((i:any) => i.pozo_id === p.id);
    const cantInscriptos = insc.length;
    const total = cantInscriptos * p.monto;
    const premio = Math.floor(total * (1 - p.comision_pct/100));

    let yaInscripto = false, yaJugo = false, cambiosRestantes = null;
    if (data.userId) {
      const miInsc = insc.find((i:any) => i.user_id === data.userId && i.estado_pago === "Aprobado");
      yaInscripto = !!miInsc;
    }

    return {
      id:p.id, fechaId:p.fecha_id, nombre:p.nombre, monto:p.monto,
      tipo:p.tipo, estado:p.estado, comisionPct:p.comision_pct,
      inscriptos:cantInscriptos, totalRecaudado:total, premioGanador:premio,
      cantPartidos, yaInscripto, yaJugo, cambiosRestantes,
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
  const mins = (new Date(fecha.plazo_limite).getTime() - Date.now()) / 60000;
  if (mins <= MINUTOS_CIERRE) return {ok:false, error:"Plazo vencido"};

  // Verificar si ya está inscripto
  const {data: yaInsc} = await db.from("inscripciones")
    .select("*").eq("user_id", auth.userId).eq("pozo_id", pozoId)
    .in("estado_pago",["Pendiente","Aprobado"]).single();

  if (yaInsc?.estado_pago === "Aprobado") return {ok:true, inscripcionId:yaInsc.id, habilitado:true};
  if (yaInsc?.estado_pago === "Pendiente") return {ok:true, inscripcionId:yaInsc.id, habilitado:false};

  const {data: user} = await db.from("usuarios").select("usuario").eq("id", auth.userId).single();
  const id = generarId("INS");
  await db.from("inscripciones").insert({
    id, user_id:auth.userId, usuario:user?.usuario, fecha_id:fechaId, pozo_id:pozoId,
    estado_pago:"Pendiente", habilitado:false,
  });

  return {ok:true, inscripcionId:id, habilitado:false};
}

// ============================================================
//  GET MIS INSCRIPCIONES
// ============================================================
async function getMisInscripciones(db: any, data: any) {
  const auth = await requireAuth(db, data);
  if (!auth.ok) return auth;

  const {data: insc} = await db.from("inscripciones")
    .select("*, pozos(monto)")
    .eq("user_id", auth.userId).eq("estado_pago","Aprobado");

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
    .select("id").eq("user_id",auth.userId).eq("fecha_id",fechaId).eq("pozo_id",pozoId).eq("estado_pago","Aprobado").single();
  if (!insc) return {ok:false, error:"No habilitado"};

  // Leer partidos y pronósticos existentes en paralelo
  const [{data:parts}, {data:existentes}] = await Promise.all([
    db.from("partidos").select("id,fecha_hora,numero").eq("fecha_id",fechaId),
    db.from("pronosticos").select("*").eq("user_id",auth.userId).eq("fecha_id",fechaId).eq("pozo_id",pozoId),
  ]);

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
    if (esCambio && cambiosUsados >= MAX_CAMBIOS) continue;

    upserts.push({
      id: existente?.id || generarId("PRO"),
      user_id: auth.userId, usuario: user?.usuario,
      fecha_id: fechaId, pozo_id: pozoId, partido_id: p.partidoId,
      numero_partido: part.numero, local: part.local, visita: part.visita,
      pronostico: p.pronostico, updated_at: new Date().toISOString(),
      cambios_realizados: existente ? (existente.cambios_realizados||0)+(esCambio?1:0) : 0,
    });
    if (esCambio) cambiosUsados++;
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
    {data:pronos}, {data:reglas}, {data:puntos}, {data:parts}
  ] = await Promise.all([
    db.from("pronosticos").select("*").eq("user_id",auth.userId).eq("fecha_id",fechaId).eq("pozo_id",pozoId),
    db.from("reglas").select("*").eq("user_id",auth.userId).eq("fecha_id",fechaId).eq("pozo_id",pozoId),
    db.from("puntajes").select("*").eq("user_id",auth.userId).eq("fecha_id",fechaId).eq("pozo_id",pozoId),
    db.from("partidos").select("*").eq("fecha_id",fechaId).order("numero"),
  ]);

  const ahora = new Date();
  const cambiosUsados = (pronos||[]).reduce((t:number,p:any) => t+(p.cambios_realizados||0), 0);

  const resultado = (pronos||[]).map((pr:any) => {
    const part = parts?.find((p:any) => p.id === pr.partido_id);
    const pts = puntos?.find((p:any) => p.partido_id === pr.partido_id);
    const reglasPartido = (reglas||[]).filter((r:any) => r.partido_id === pr.partido_id);
    const diffMin = part?.fecha_hora ? (new Date(part.fecha_hora).getTime() - ahora.getTime()) / 60000 : 9999;
    return {
      id:pr.id, partidoId:pr.partido_id, numero:pr.numero_partido,
      local:pr.local, visita:pr.visita, pronostico:pr.pronostico,
      acertado:pr.acertado, cambiosRealizados:pr.cambios_realizados||0,
      puedeCambiar:diffMin>MINUTOS_CIERRE,
      reglas:reglasPartido.map((r:any) => ({codigo:r.codigo,nombre:r.nombre,detalle:r.detalle,puntos:r.puntos_obtenidos||0})),
      ptsGrilla:pts?(pts.pts_normal+pts.pts_doble+pts.pts_polla):null,
      ptsToleTole:pts?pts.pts_tole:null,
      ptsReglas:pts?pts.pts_reglas:null,
      ptsTotal:pts?pts.pts_total:null,
      esToleTole:pts?pts.es_tole:null,
      calculado:!!pts,
    };
  });

  const reglasMap = (reglas||[]).map((r:any) => {
    const part = parts?.find((p:any) => p.id === r.partido_id);
    const diffMin = part?.fecha_hora ? (new Date(part.fecha_hora).getTime() - ahora.getTime()) / 60000 : 9999;
    return {partidoId:r.partido_id, codigo:r.codigo, nombre:r.nombre, detalle:r.detalle, puntos:r.puntos_obtenidos||0, esMovible:diffMin>MINUTOS_CIERRE};
  });

  return {ok:true, pronos:resultado, reglas:reglasMap, totalPartidos:parts?.length||0, totalCompletos:resultado.length, cambiosRestantesFecha:Math.max(0,MAX_CAMBIOS-cambiosUsados)};
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
    .select("id").eq("user_id",auth.userId).eq("fecha_id",fechaId).eq("pozo_id",pozoId).eq("estado_pago","Aprobado").single();
  if (!insc) return {ok:false, error:"No habilitado"};

  const {data: user} = await db.from("usuarios").select("usuario").eq("id",auth.userId).single();
  const {data: parts} = await db.from("partidos").select("*").eq("fecha_id",fechaId);
  const ahora = new Date();
  const nuevas: any[] = [];
  const codigosNuevos = reglas.map((r:any) => r.codigo);

  // Eliminar reglas anteriores de los mismos códigos
  await db.from("reglas").delete()
    .eq("user_id",auth.userId).eq("fecha_id",fechaId).eq("pozo_id",pozoId)
    .in("codigo",codigosNuevos);

  for (const reg of reglas) {
    const def = REGLAS_DEF[reg.codigo];
    if (!def) continue;
    for (const pid of (reg.partidos||[])) {
      const part = parts?.find((p:any) => p.id===pid);
      if (!part) continue;
      // Solo bloquear si el partido tiene fecha_hora válida Y ya cerró
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
    }
  }

  if (nuevas.length) await db.from("reglas").insert(nuevas);
  return {ok:true, guardadas:nuevas.length};
}

// ============================================================
//  GET TABLA
// ============================================================
async function getTabla(db: any, data: any) {
  const {data: pts} = await db.from("puntajes")
    .select("user_id,usuario,pts_total,acertado")
    .eq("fecha_id",data.fechaId).eq("pozo_id",data.pozoId);

  const usuarios: Record<string,any> = {};
  for (const p of (pts||[])) {
    if (!usuarios[p.user_id]) usuarios[p.user_id] = {userId:p.user_id, siglas:p.usuario, ptsTotal:0, acertados:0};
    usuarios[p.user_id].ptsTotal += p.pts_total||0;
    if (p.acertado) usuarios[p.user_id].acertados++;
  }

  const tabla = Object.values(usuarios).sort((a:any,b:any) => b.ptsTotal-a.ptsTotal || b.acertados-a.acertados)
    .map((u:any,i:number) => ({...u, posicion:i+1}));

  return {ok:true, tabla};
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
  });
  if (error) return {ok:false, error:error.message};
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
  await db.from("fechas").update(upd).eq("id",data.fechaId);
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
    id, fecha_id:data.fechaId, nombre:data.nombre||`Pozo $${data.monto}`,
    monto:data.monto, comision_pct:25,
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

  await db.from("partidos").update({
    estado:"Finalizado", goles_local:gL, goles_visita:gV,
    resultado, tarjetas_rojas:data.tarjetasRojas||0,
    ultimo_update:new Date().toISOString(),
  }).eq("id",data.partidoId);

  // Calcular puntajes
  await calcularPuntajesPartido(db, data.partidoId);

  return {ok:true, resultado};
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
const LIGA_IDS: Record<string,number> = {
  "Liga Argentina":128,"Serie A":135,"La Liga":140,"Ligue 1":61,
  "Premier League":39,"Champions League":2,"Copa Libertadores":13,
};
const TEMPORADA = 2024;
const AF_KEY = Deno.env.get("APIFOOTBALL_KEY") || "3ea8d01a35fbc69e57a1ea4ce7cf55e8";

async function callAPIFootball(endpoint: string, params: Record<string,any>) {
  const url = `https://v3.football.api-sports.io/${endpoint}?` + new URLSearchParams(
    Object.fromEntries(Object.entries(params).filter(([,v]) => v!=null).map(([k,v]) => [k,String(v)]))
  );
  const r = await fetch(url, {headers:{"x-apisports-key":AF_KEY}});
  return r.json();
}

async function getRondas(db: any, data: any) {
  const ligaId = LIGA_IDS[data.liga];
  if (!ligaId) return {ok:false, error:"Liga no reconocida"};
  const res = await callAPIFootball("fixtures/rounds", {league:ligaId, season:data.temporada||TEMPORADA});
  return {ok:true, rondas:res.response||[]};
}

async function buscarPorRonda(db: any, data: any) {
  const ligaId = LIGA_IDS[data.liga];
  if (!ligaId) return {ok:false, error:"Liga no reconocida"};
  const res = await callAPIFootball("fixtures", {league:ligaId, season:data.temporada||TEMPORADA, round:data.ronda, timezone:"America/Argentina/Buenos_Aires"});
  const partidos = (res.response||[]).map((f:any) => ({
    apiId:f.fixture.id, fecha:f.fixture.date, local:f.teams.home.name, visita:f.teams.away.name,
    localLogo:f.teams.home.logo, visitaLogo:f.teams.away.logo,
    golesLocal:f.goals.home, golesVisita:f.goals.away,
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
  const {data: users} = await db.from("usuarios").select("id,telefono,usuario,nombre,alias_mp,email,estado,rol,created_at").order("created_at");
  return {ok:true, usuarios:users||[]};
}

// ============================================================
//  CALCULAR PUNTAJES (lógica completa)
// ============================================================
async function calcularPuntajesPartido(db: any, partidoId: string) {
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
  const esTole = pctL<TOLE_UMBRAL&&pctE<TOLE_UMBRAL&&pctV<TOLE_UMBRAL;

  const puntajesUpsert: any[] = [];
  const pronosUpdate: any[] = [];
  const reglasUpdate: any[] = [];

  for (const pr of (pronos||[])) {
    const acertado = pr.pronostico === part.resultado;
    pronosUpdate.push({id:pr.id, acertado});

    let ptsN=0,ptsD=0,ptsP=0,ptsTole=0,ptsR=0;
    if (acertado) {
      if (part.tipo==="Normal") ptsN=PTS_NORMAL;
      else if (part.tipo==="Doble") ptsD=PTS_DOBLE;
      else if (part.tipo==="Polla") ptsP=PTS_POLLA;
      if (esTole) ptsTole=TOLE_PTS;

      const misReglas = (reglas||[]).filter((r:any)=>r.user_id===pr.user_id&&r.pozo_id===pr.pozo_id);
      for (const reg of misReglas) {
        const pts = calcPtsRegla(reg, part.resultado, part.goles_local||0, part.goles_visita||0, part.tarjetas_rojas||0);
        ptsR += pts;
        reglasUpdate.push({id:reg.id, puntos_obtenidos:pts});
      }
    } else {
      // Reglas que no dependen del pronóstico (LMR)
      const misReglas = (reglas||[]).filter((r:any)=>r.user_id===pr.user_id&&r.pozo_id===pr.pozo_id);
      for (const reg of misReglas) {
        if (reg.codigo==="LMR") {
          const pts = part.tarjetas_rojas||0;
          ptsR += pts;
          reglasUpdate.push({id:reg.id, puntos_obtenidos:pts});
        } else {
          reglasUpdate.push({id:reg.id, puntos_obtenidos:0});
        }
      }
    }

    const ptsTotal = ptsN+ptsD+ptsP+ptsTole+ptsR;
    puntajesUpsert.push({
      id:generarId("PTS"), user_id:pr.user_id, usuario:pr.usuario,
      fecha_id:part.fecha_id, pozo_id:pr.pozo_id, partido_id:partidoId,
      numero_partido:part.numero, local:part.local, visita:part.visita,
      resultado_real:part.resultado, pronostico:pr.pronostico,
      acertado, pts_normal:ptsN, pts_doble:ptsD, pts_polla:ptsP,
      pts_tole:ptsTole, pts_reglas:ptsR, pts_total:ptsTotal, es_tole:esTole,
    });
  }

  // Ejecutar updates en paralelo
  await Promise.all([
    ...pronosUpdate.map((p:any) => db.from("pronosticos").update({acertado:p.acertado}).eq("id",p.id)),
    puntajesUpsert.length ? db.from("puntajes").upsert(puntajesUpsert, {onConflict:"user_id,partido_id,pozo_id"}) : Promise.resolve(),
    ...reglasUpdate.map((r:any) => db.from("reglas").update({puntos_obtenidos:r.puntos_obtenidos}).eq("id",r.id)),
  ]);

  // Calcular LR post-partido
  await calcularLRpostPartido(db, part.fecha_id);
}

function calcPtsRegla(reg:any, resultado:string, gL:number, gV:number, rojas:number): number {
  switch(reg.codigo) {
    case "LMR": return rojas;
    case "LLDG": return (gL+gV)>=5?4:0;
    case "GSA": return (gL>0&&gV>0)?(gL+gV):0;
    case "ZPL": return Math.abs(gL-gV)>=3?4:0;
    case "EQS": return resultado==="E"?3:0;
    case "MK": {
      const p=(reg.detalle||"").split("-").map(Number);
      return p.length===2&&p[0]===gL&&p[1]===gV?5:0;
    }
    case "LR": case "DIEGO": return 0;
    default: return 0;
  }
}

async function calcularLRpostPartido(db: any, fechaId: string) {
  const [{data:pronos},{data:reglas},{data:puntos}] = await Promise.all([
    db.from("pronosticos").select("*").eq("fecha_id",fechaId).order("numero_partido"),
    db.from("reglas").select("*").eq("fecha_id",fechaId).in("codigo",["LR","DIEGO"]),
    db.from("puntajes").select("*").eq("fecha_id",fechaId),
  ]);

  const users = [...new Set((pronos||[]).map((p:any) => p.user_id+"|"+p.pozo_id))];

  for (const key of users) {
    const [userId, pozoId] = key.split("|");
    const misPronos = (pronos||[]).filter((p:any)=>p.user_id===userId&&p.pozo_id===pozoId).sort((a:any,b:any)=>a.numero_partido-b.numero_partido);
    const misReglas = (reglas||[]).filter((r:any)=>r.user_id===userId&&r.pozo_id===pozoId);

    // LR
    const reglaLR = misReglas.find((r:any)=>r.codigo==="LR");
    if (reglaLR) {
      const numInicio = reglaLR.numero_partido;
      const racha = misPronos.filter((p:any)=>p.numero_partido>=numInicio).slice(0,3);
      const mults = [1,2,4];
      let ptsLR = 0;
      for (let i=0;i<racha.length;i++) {
        if (racha[i].acertado===true) ptsLR+=mults[i]; else break;
      }
      const ptsViejo = reglaLR.puntos_obtenidos||0;
      await db.from("reglas").update({puntos_obtenidos:ptsLR}).eq("id",reglaLR.id);
      if (ptsLR!==ptsViejo) {
        const pts = puntos?.find((p:any)=>p.user_id===userId&&p.pozo_id===pozoId);
        if (pts) await db.from("puntajes").update({pts_reglas:pts.pts_reglas-ptsViejo+ptsLR, pts_total:pts.pts_total-ptsViejo+ptsLR}).eq("id",pts.id);
      }
    }
  }
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
  if (data.avatar) upd.avatar = data.avatar;
  if (data.pin) upd.pin_hash = await hashPinAsync(data.pin);
  await db.from("usuarios").update(upd).eq("id", auth.userId);
  return {ok:true};
}

// ============================================================
//  GET GRILLA (pronósticos de todos)
// ============================================================
async function getGrilla(db: any, data: any) {
  const {fechaId, pozoId} = data;
  const [{data: pronos}, {data: parts}, {data: users}] = await Promise.all([
    db.from("pronosticos").select("user_id,usuario,partido_id,pronostico,acertado").eq("fecha_id",fechaId).eq("pozo_id",pozoId),
    db.from("partidos").select("id,numero,local,visita,resultado").eq("fecha_id",fechaId).order("numero"),
    db.from("puntajes").select("user_id,usuario,pts_total").eq("fecha_id",fechaId).eq("pozo_id",pozoId),
  ]);

  const ptsMap: Record<string,number> = {};
  (users||[]).forEach((u:any) => { ptsMap[u.user_id] = (ptsMap[u.user_id]||0) + u.pts_total; });

  const jugadores: Record<string,any> = {};
  (pronos||[]).forEach((p:any) => {
    if (!jugadores[p.user_id]) jugadores[p.user_id] = {userId:p.user_id, siglas:p.usuario, pronos:{}, ptsTotal:ptsMap[p.user_id]||0};
    jugadores[p.user_id].pronos[p.partido_id] = {v:p.pronostico, ok:p.acertado};
  });

  return {ok:true, partidos:parts||[], jugadores:Object.values(jugadores).sort((a:any,b:any) => b.ptsTotal-a.ptsTotal)};
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

  return {ok:true, calculados:parts?.length||0};
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
async function getGrupoPorCodigo(db: any, data: any) {
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
