import helmet from 'helmet';
import type { Request, Response } from 'express';

export const policies =
  (allowIframe: boolean) =>
  (req: Request, res: Response, next: (err?: unknown) => void): void => {
    helmet({
      referrerPolicy: { policy: ['no-referrer-when-downgrade'] },
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          // The xterm image decoder uses WebAssembly, but needs no JS eval.
          scriptSrc: ["'self'", "'wasm-unsafe-eval'"],
          scriptSrcAttr: ["'none'"],
          objectSrc: ["'none'"],
          baseUri: ["'none'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          fontSrc: ["'self'", 'data:'],
          connectSrc: [
            "'self'",
            `${req.protocol === 'http' ? 'ws://' : 'wss://'}${req.get('host') ?? ''}`,
          ],
        },
      },
      xFrameOptions: allowIframe ? false : { action: 'sameorigin' },
    })(req, res, next);
  };
