// Invoked by OpenSSH KnownHostsCommand, not by a shell. No trust is stored here.
import { createConnection } from 'node:net';
import { fields } from '../../shared/browserAgent.js';

const [path, reason, type, key] = process.argv.slice(2);
const socket = createConnection(path);
let buffer = '';
let complete = false;
function fail(): void {
  process.exitCode = 1;
  socket.destroy();
}
socket.setTimeout(125000, fail);
socket.on('error', fail);
socket.on('connect', () => {
  socket.write(`${JSON.stringify({ reason, type, key })}\n`);
});
socket.on('data', (chunk: Buffer) => {
  buffer += chunk.toString('utf8');
  if (buffer.length > 10000) {
    fail();
    return;
  }
  if (!buffer.endsWith('\n')) return;
  try {
    const response = fields(JSON.parse(buffer));
    if (typeof response.line !== 'string' || /[\r\n]/.test(response.line)) {
      throw new Error('Invalid helper reply');
    }
    complete = true;
    if (response.line) process.stdout.write(`${response.line}\n`);
    socket.end();
  } catch {
    fail();
  }
});
socket.on('close', () => {
  if (!complete) process.exitCode = 1;
});
