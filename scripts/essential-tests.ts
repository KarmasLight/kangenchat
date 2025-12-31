import io, { Socket } from 'socket.io-client';

const getArg = (name: string) => {
  const prefix = `--${name}=`;
  const match = process.argv.slice(2).find((arg) => arg.startsWith(prefix));
  return match ? match.slice(prefix.length) : undefined;
};

const BACKEND_URL = getArg('backend') || process.env.TEST_BACKEND_URL || 'http://localhost:5010';
const CONNECT_TIMEOUT_MS = parseInt(getArg('connectTimeout') || process.env.TEST_CONNECT_TIMEOUT || '5000', 10);
const MESSAGE_TIMEOUT_MS = parseInt(getArg('messageTimeout') || process.env.TEST_MESSAGE_TIMEOUT || '5000', 10);

if (!Number.isFinite(CONNECT_TIMEOUT_MS) || CONNECT_TIMEOUT_MS <= 0) {
  throw new Error('CONNECT_TIMEOUT_MS must be a positive integer');
}

if (!Number.isFinite(MESSAGE_TIMEOUT_MS) || MESSAGE_TIMEOUT_MS <= 0) {
  throw new Error('MESSAGE_TIMEOUT_MS must be a positive integer');
}

type MessageEvent = {
  sessionId: string;
  role: 'USER' | 'AGENT';
  content: string;
  createdAt?: string;
  agentId?: string | null;
};

type Waiter = {
  predicate: (msg: MessageEvent) => boolean;
  afterSeq: number;
  resolve: (msg: MessageEvent) => void;
  reject: (err: Error) => void;
  timer: NodeJS.Timeout;
};

class MessageTracker {
  private entries: { seq: number; message: MessageEvent }[] = [];
  private waiters: Waiter[] = [];
  private seq = 0;

  push(message: MessageEvent) {
    const entry = { seq: ++this.seq, message };
    this.entries.push(entry);
    this.waiters = this.waiters.filter((waiter) => {
      if (entry.seq <= waiter.afterSeq) {
        return true;
      }
      if (waiter.predicate(message)) {
        clearTimeout(waiter.timer);
        waiter.resolve(message);
        return false;
      }
      return true;
    });
  }

  getCursor() {
    return this.seq;
  }

  wait(predicate: (msg: MessageEvent) => boolean, timeoutMs: number, afterSeq: number) {
    const existing = this.entries.find((entry) => entry.seq > afterSeq && predicate(entry.message));
    if (existing) {
      return Promise.resolve(existing.message);
    }

    return new Promise<MessageEvent>((resolve, reject) => {
      const waiter: Waiter = {
        predicate,
        afterSeq,
        resolve: (msg) => {
          this.waiters = this.waiters.filter((w) => w !== waiter);
          resolve(msg);
        },
        reject: (err) => {
          this.waiters = this.waiters.filter((w) => w !== waiter);
          reject(err);
        },
        timer: setTimeout(() => {
          waiter.reject(new Error('Timed out waiting for message'));
        }, timeoutMs),
      };
      this.waiters.push(waiter);
    });
  }

  clearWaiters() {
    this.waiters.forEach((waiter) => clearTimeout(waiter.timer));
    this.waiters = [];
  }
}

const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

async function createSession(visitorLabel: string) {
  const response = await fetch(`${BACKEND_URL}/sessions`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      issueType: 'EssentialTests',
      message: `Initial message from ${visitorLabel}`,
    }),
  });
  if (!response.ok) {
    throw new Error(`Failed to create session: ${response.status}`);
  }
  return (await response.json()) as { sessionId: string; visitorId: string };
}

const onceConnected = (socket: Socket) =>
  new Promise<void>((resolve, reject) => {
    const onConnect = () => {
      socket.off('connect_error', onError);
      resolve();
    };
    const onError = (err: Error) => {
      socket.off('connect', onConnect);
      reject(err);
    };
    socket.once('connect', onConnect);
    socket.once('connect_error', onError);
  });

const emitWithAck = (socket: Socket, event: string, payload: unknown, timeoutMs = 4000) =>
  new Promise<void>((resolve, reject) => {
    let finished = false;
    const timer = setTimeout(() => {
      if (finished) return;
      finished = true;
      reject(new Error(`Ack timeout for event ${event}`));
    }, timeoutMs);

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
  });

type TestContext = {
  sessionId: string;
  visitorId: string;
  tracker: MessageTracker;
  sendMessage: (content: string) => Promise<void>;
  waitForBotMessage: (
    predicate: (msg: MessageEvent) => boolean,
    timeoutMs?: number,
    afterSeq?: number
  ) => Promise<MessageEvent>;
};

type EssentialTest = {
  name: string;
  description: string;
  run: (ctx: TestContext) => Promise<void>;
};

const essentialTests: EssentialTest[] = [
  {
    name: 'quick-reply-requires-name',
    description: 'Quick replies should not satisfy the name prompt and must trigger a reminder.',
    run: async (ctx) => {
      const cursor = ctx.tracker.getCursor();
      await ctx.sendMessage('Warranty & repairs');
      await ctx.waitForBotMessage(
        (msg) => msg.content.toLowerCase().includes('first and last name'),
        MESSAGE_TIMEOUT_MS,
        cursor
      );
    },
  },
  {
    name: 'manual-name-accepted',
    description: 'Providing a proper name should be acknowledged by the bot greeting.',
    run: async (ctx) => {
      const cursor = ctx.tracker.getCursor();
      await ctx.sendMessage('My name is Essential Tester');
      await ctx.waitForBotMessage(
        (msg) => msg.content.toLowerCase().startsWith('nice to meet you'),
        MESSAGE_TIMEOUT_MS,
        cursor
      );
    },
  },
  {
    name: 'handoff-contact-info-flow',
    description: 'Requesting a live agent should prompt for email and phone before queuing.',
    run: async (ctx) => {
      const handoffCursor = ctx.tracker.getCursor();
      await ctx.sendMessage('I need a live agent');
      await ctx.waitForBotMessage(
        (msg) => msg.content.toLowerCase().includes('before i loop in a teammate'),
        MESSAGE_TIMEOUT_MS,
        handoffCursor
      );

      const emailCursor = ctx.tracker.getCursor();
      await ctx.sendMessage('essential.test@example.com');
      await ctx.waitForBotMessage(
        (msg) => msg.content.toLowerCase().includes('got your email'),
        MESSAGE_TIMEOUT_MS,
        emailCursor
      );

      const phoneCursor = ctx.tracker.getCursor();
      await ctx.sendMessage('+1 555 867 5309');
      await ctx.waitForBotMessage(
        (msg) => msg.content.toLowerCase().includes('thanks for the phone number'),
        MESSAGE_TIMEOUT_MS,
        phoneCursor
      );
    },
  },
];

async function runEssentialSuite() {
  console.log(`Running essential tests against ${BACKEND_URL}`);
  const { sessionId, visitorId } = await createSession('essential-test');

  const socket = io(BACKEND_URL, {
    transports: ['websocket'],
    timeout: CONNECT_TIMEOUT_MS,
    forceNew: true,
  });

  const tracker = new MessageTracker();
  socket.on('new_message', (message: MessageEvent) => tracker.push(message));

  try {
    await onceConnected(socket);
    await emitWithAck(socket, 'visitor_join', { sessionId, visitorId });

    const ctx: TestContext = {
      sessionId,
      visitorId,
      tracker,
      sendMessage: async (content: string) => {
        await emitWithAck(socket, 'send_message', { sessionId, role: 'USER', content });
        await delay(150); // brief pause so server can enqueue follow-up messages
      },
      waitForBotMessage: (predicate, timeoutMs = MESSAGE_TIMEOUT_MS, afterSeq = 0) =>
        tracker.wait((msg) => msg.role === 'AGENT' && predicate(msg), timeoutMs, afterSeq),
    };

    const results = [] as { name: string; description: string; status: 'PASS' | 'FAIL'; details?: string }[];

    for (const test of essentialTests) {
      try {
        await test.run(ctx);
        results.push({ name: test.name, description: test.description, status: 'PASS' });
        console.log(`✅ ${test.name}`);
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        results.push({ name: test.name, description: test.description, status: 'FAIL', details: message });
        console.error(`❌ ${test.name}: ${message}`);
        break;
      }
    }

    console.table(results);
    const failed = results.find((r) => r.status === 'FAIL');
    if (failed) {
      process.exitCode = 1;
    }
  } finally {
    tracker.clearWaiters();
    if (socket.connected) {
      socket.disconnect();
    }
  }
}

runEssentialSuite().catch((err) => {
  console.error('Essential test suite crashed', err);
  process.exit(1);
});
