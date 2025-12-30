import { io, Socket } from 'socket.io-client';

export const BACKEND_URL = process.env.NEXT_PUBLIC_BACKEND_URL || 'http://localhost:3010';

// Extend Socket with the same auth shape used by socket.io-client types
export type AgentSocket = Socket & {
  auth: Record<string, unknown> | ((cb: (data: object) => void) => void);
};

let socketInstance: AgentSocket | null = null;

export const getAgentSocket = (): AgentSocket => {
  if (!socketInstance) {
    socketInstance = io(BACKEND_URL, { autoConnect: false }) as AgentSocket;
  }
  return socketInstance;
};
