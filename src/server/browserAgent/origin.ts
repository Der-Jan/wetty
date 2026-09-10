import type { ServerOptions } from 'socket.io';

/** Restrict both Socket.IO transports without requiring Origin on same-origin GETs. */
export function browserOriginOptions(origin?: string): Partial<ServerOptions> {
  if (!origin) return {};
  return {
    allowRequest: (request, callback) => {
      // An explicit Origin always wins over Fetch Metadata and Referer.
      let allowed = request.headers.origin === origin;
      if (
        request.headers.origin === undefined &&
        request.headers['sec-fetch-site'] === 'same-origin' &&
        request.headers.referer
      ) {
        try {
          allowed = new URL(request.headers.referer).origin === origin;
        } catch {
          allowed = false;
        }
      }
      callback(null, allowed);
    },
  };
}
