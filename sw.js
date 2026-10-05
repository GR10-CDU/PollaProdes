// Polla Prodes: service worker para instalar la app y recibir avisos (notificaciones push).
// No guarda nada en caché: siempre trae la versión publicada (los datos vienen en vivo del servidor).
self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", e => e.waitUntil(self.clients.claim()));
self.addEventListener("fetch", () => {});

self.addEventListener("push", e => {
  let d = {};
  try { d = e.data ? e.data.json() : {}; } catch (_) { d = {title: "Polla Prodes", body: e.data && e.data.text()}; }
  e.waitUntil(self.registration.showNotification(d.title || "Polla Prodes", {
    body: d.body || "", tag: d.tag || undefined, icon: "icons/icon-192.png", badge: "icons/icon-192.png",
    data: {url: d.url || "./"}, vibrate: [80, 40, 80],
  }));
});

self.addEventListener("notificationclick", e => {
  e.notification.close();
  const url = new URL((e.notification.data && e.notification.data.url) || "./", self.registration.scope).href;
  e.waitUntil(clients.matchAll({type: "window", includeUncontrolled: true}).then(ws => {
    const ir = new URL(url).searchParams.get("ir");
    for (const w of ws) if (w.url.startsWith(self.registration.scope)) { if (ir) w.postMessage({ir}); return w.focus(); }
    return clients.openWindow(url);
  }));
});
