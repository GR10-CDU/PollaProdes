// Polla Prodes: service worker mínimo para que el celular la pueda instalar como app.
// No guarda nada en caché: siempre trae la versión publicada (los datos vienen en vivo del servidor).
self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", e => e.waitUntil(self.clients.claim()));
self.addEventListener("fetch", () => {});
