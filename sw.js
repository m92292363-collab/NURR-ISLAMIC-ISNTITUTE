// NURR admin desktop app — always loads the latest version online.
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));
self.addEventListener('fetch', e => {
  if (e.request.mode !== 'navigate') return;
  e.respondWith(fetch(e.request).catch(() => new Response(
    '<!DOCTYPE html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Offline</title>' +
    '<body style="font-family:Arial,sans-serif;background:#0d3b6e;color:#fff;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;text-align:center">' +
    '<div><h2>No internet connection</h2><p>The admin needs internet. Check your connection and try again.</p>' +
    '<button onclick="location.reload()" style="padding:10px 22px;border:0;border-radius:8px;font-size:15px;cursor:pointer">Try again</button></div>',
    { headers: { 'Content-Type': 'text/html; charset=utf-8' } })));
});
