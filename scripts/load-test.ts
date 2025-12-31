import io from 'socket.io-client';

const getArg = (name: string) => {
  const prefix = `--${name}=`;
  const match = process.argv.slice(2).find((arg) => arg.startsWith(prefix));
  return match ? match.slice(prefix.length) : undefined;
};

const BACKEND_URL = getArg('backend') || process.env.LOAD_BACKEND_URL || 'http://localhost:5010';
const VISITOR_COUNT = parseInt(getArg('users') || process.env.LOAD_USERS || '10', 10);
const MESSAGES_PER_VISITOR = parseInt(getArg('messages') || process.env.LOAD_MESSAGES || '3', 10);
const MESSAGE_INTERVAL_MS = parseInt(getArg('interval') || process.env.LOAD_INTERVAL_MS || '1200', 10);
const CONNECT_TIMEOUT_MS = parseInt(getArg('connectTimeout') || process.env.LOAD_CONNECT_TIMEOUT || '5000', 10);

if (!Number.isFinite(VISITOR_COUNT) || VISITOR_COUNT <= 0) {
  throw new Error('VISITOR_COUNT must be a positive integer');
}

if (!Number.isFinite(MESSAGES_PER_VISITOR) || MESSAGES_PER_VISITOR < 0) {
  throw new Error('MESSAGES_PER_VISITOR must be zero or a positive integer');
}

const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

async function createSession(visitorLabel: string) {
  const response = await fetch(`${BACKEND_URL}/sessions`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      issueType: 'LoadTest',
      message: `Load test bootstrap from ${visitorLabel}`,
    }),
  });
  if (!response.ok) {
    throw new Error(`Failed to create session for ${visitorLabel}: ${response.status}`);
  }
  const data = (await response.json()) as { sessionId: string; visitorId: string };
  return data;
}

const emitWithAck = (socket: ReturnType<typeof io>, event: string, payload: unknown, timeoutMs = 4000) =>
  new Promise<void>((resolve, reject) => {
    let finished = false;
    const timer = setTimeout(() => {
      if (finished) return;
      finished = true;
      reject(new Error(`Ack timeout for event ${event}`));
    }, timeoutMs);

    try {
      socket.emit(event, payload, (resp?: { error?: string }) => {
        if (finished) return;
        finished = true;
        clearTimeout(timer);
        if (resp && resp.error) {
          reject(new Error(resp.error));
        } else {
          resolve();
        }
      });
    } catch (err) {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      reject(err);
    }
  });

type SimulationResult = {
  label: string;
  sent: number;
  errors: number;
  durationMs: number;
};

async function simulateVisitor(index: number): Promise<SimulationResult> {
  const label = `visitor-${index}`;
  const start = Date.now();
  const result: SimulationResult = { label, sent: 0, errors: 0, durationMs: 0 };

  try {
    const { sessionId, visitorId } = await createSession(label);

    await new Promise<void>((resolve, reject) => {
      const socket = io(BACKEND_URL, {
        transports: ['websocket'],
        timeout: CONNECT_TIMEOUT_MS,
        forceNew: true,
      });

      const finish = (err?: Error) => {
        if (socket.connected) {
          socket.disconnect();
        }
        if (err) {
          result.errors += 1;
          reject(err);
        } else {
          resolve();
        }
      };

      const runFlow = async () => {
        try {
          await emitWithAck(socket, 'visitor_join', { sessionId, visitorId });
          await emitWithAck(socket, 'send_message', {
            sessionId,
            role: 'USER',
            content: `My name is Load Tester ${index}`,
          });
          result.sent += 1;

          for (let i = 0; i < MESSAGES_PER_VISITOR; i += 1) {
            await delay(MESSAGE_INTERVAL_MS);
            await emitWithAck(socket, 'send_message', {
              sessionId,
              role: 'USER',
              content: `This is automated message #${i + 1} from visitor ${index}`,
            });
            result.sent += 1;
          }

          finish();
        } catch (err) {
          finish(err instanceof Error ? err : new Error(String(err)));
        }
      };

      socket.on('connect', runFlow);
      socket.on('connect_error', (err) => finish(err instanceof Error ? err : new Error('connect_error')));
    });
  } catch (err) {
    result.errors += 1;
    console.error(`[${label}] simulation failed`, err);
  } finally {
    result.durationMs = Date.now() - start;
  }

  return result;
}

async function main() {
  console.log(
    `Starting load test: ${VISITOR_COUNT} visitors, ${MESSAGES_PER_VISITOR} additional messages each (interval ${MESSAGE_INTERVAL_MS}ms) hitting ${BACKEND_URL}`
  );

  const simulations = Array.from({ length: VISITOR_COUNT }, (_, idx) => simulateVisitor(idx + 1));
  const results = await Promise.all(simulations);

  const totalSent = results.reduce((sum, r) => sum + r.sent, 0);
  const totalErrors = results.reduce((sum, r) => sum + r.errors, 0);
  const totalDuration = results.reduce((sum, r) => sum + r.durationMs, 0) / results.length || 0;

  console.table(results);
  console.log(`Messages sent: ${totalSent}`);
  console.log(`Visitors with errors: ${totalErrors}`);
  console.log(`Average duration per visitor: ${totalDuration.toFixed(0)}ms`);

  if (totalErrors > 0) {
    process.exitCode = 1;
  }
}

main().catch((err) => {
  console.error('Load test script crashed', err);
  process.exit(1);
});
