import { io, type Socket } from 'socket.io-client';

export const trim = (str: string): string => str.replace(/\/*$/, '');

const socketBase = trim(window.location.pathname).replace(/ssh\/[^/]+$/, '');
export const socket: Socket = io(window.location.origin, {
  autoConnect: false,
  path: `${trim(socketBase)}/socket.io`,
});
