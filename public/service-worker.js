// AteraMedia Passwords Manager — Service Worker
// Cachea toda la app (app shell + librerías + fuentes) para que funcione 100% offline
// una vez instalada/visitada por primera vez.
const CACHE_NAME = 'supreme-key-cache-v8';
const ASSETS = [
  './',
  './index.html',
  './manifest.json',
  './vendor/crypto-js.min.js',
  './vendor/jspdf.umd.min.js',
  './vendor/jspdf.plugin.autotable.min.js',
  './vendor/fonts/fraunces-400.woff2',
  './vendor/fonts/fraunces-500.woff2',
  './vendor/fonts/fraunces-600.woff2',
  './vendor/fonts/fraunces-700.woff2',
  './vendor/fonts/inter-400.woff2',
  './vendor/fonts/inter-500.woff2',
  './vendor/fonts/inter-600.woff2',
  './vendor/fonts/inter-700.woff2',
  './vendor/fonts/jbmono-400.woff2',
  './vendor/fonts/jbmono-500.woff2',
  './vendor/fonts/jbmono-600.woff2',
  './icons/icon-96.png',
  './icons/icon-192.png',
  './icons/icon-512.png',
  './icons/apple-touch-icon.png',
  './icons/favicon-32.png'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(ASSETS)).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

// Cache-first: sirve desde caché de inmediato; si hay red, actualiza la caché en segundo plano.
self.addEventListener('fetch', (event) => {
  if (event.request.method !== 'GET') return;
  event.respondWith(
    caches.match(event.request).then((cached) => {
      const network = fetch(event.request)
        .then((resp) => {
          if (resp && resp.status === 200) {
            const clone = resp.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(event.request, clone));
          }
          return resp;
        })
        .catch(() => cached);
      return cached || network;
    })
  );
});
