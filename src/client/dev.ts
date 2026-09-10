import { diagnoseSshKey } from './wetty/auth/diagnostics';

declare global {
  interface Window {
    wettyKeyDiagnostics?: typeof diagnoseSshKey;
  }
}

window.wettyKeyDiagnostics = diagnoseSshKey;

void caches.keys().then((cacheNames) => {
  cacheNames.forEach((cacheName) => {
    void caches.delete(cacheName);
  });
});
