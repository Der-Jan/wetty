import { readFile } from 'node:fs/promises';
import { expect } from 'chai';
import express from 'express';
import 'mocha';
import { html } from './html.js';
import { policies } from './security.js';

describe('Script security policy', () => {
  it('should restrict scripts on the terminal and settings document', async () => {
    const app = express();
    app.use(policies(false));
    app.get('/', html('', 'WeTTY'));
    app.get('/client/xterm_config/index.html', async (_req, res) => {
      res
        .type('html')
        .send(await readFile('src/assets/xterm_config/index.html', 'utf8'));
    });
    const server = app.listen(0, '127.0.0.1');
    try {
      await new Promise<void>((resolve) => {
        server.once('listening', resolve);
      });
      const address = server.address();
      if (!address || typeof address === 'string') {
        throw new Error('Missing port');
      }
      await Promise.all(
        ['/', '/client/xterm_config/index.html'].map(async (path) => {
          const response = await fetch(
            `http://127.0.0.1:${String(address.port)}${path}`,
          );
          const csp = response.headers.get('content-security-policy') ?? '';
          expect(csp).to.include("script-src 'self' 'wasm-unsafe-eval';");
          expect(csp).to.include("script-src-attr 'none';");
          expect(csp).to.include("object-src 'none';");
          expect(csp).to.include("base-uri 'none';");
          expect(csp).not.to.include("'unsafe-eval'");
          const body = await response.text();
          expect(body).not.to.match(/\son\w+\s*=/i);
          expect(body).not.to.match(/<script(?![^>]*\bsrc=)[^>]*>/i);
        }),
      );
    } finally {
      await new Promise<void>((resolve, reject) => {
        server.close((error) => {
          error ? reject(error) : resolve();
        });
      });
    }
  });
});
