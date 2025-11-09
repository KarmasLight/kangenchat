"use client";
import { useState, useEffect, useRef } from 'react';
import io, { Socket } from 'socket.io-client';
import { Card, CardContent, CardHeader, CardTitle, CardFooter } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { ScrollArea } from '@/components/ui/scroll-area';
import PreChatForm from '@/components/PreChatForm';

type MessageEvent = { id: string; sessionId: string; role: 'USER' | 'AGENT'; content: string; createdAt: string };
type ChatEvent = { sessionId: string };

const socket: Socket = io(process.env.NEXT_PUBLIC_BACKEND_URL || 'http://localhost:5010', { autoConnect: false });

export default function CustomerWidget() {
  const [sessionId, setSessionId] = useState<string>('');
  const [visitorId, setVisitorId] = useState<string>('');
  const [messageInput, setMessageInput] = useState<string>('');
  const [messages, setMessages] = useState<MessageEvent[]>([]);
  const [status, setStatus] = useState<string>('Disconnected');
  const [isAgentTyping, setIsAgentTyping] = useState<boolean>(false);
  const agentTypingTimerRef = useRef<number | null>(null);
  const sessionIdRef = useRef<string>('');
  const [showChat, setShowChat] = useState(false);
  const scrollAreaRef = useRef<HTMLDivElement>(null);
  const [isClosed, setIsClosed] = useState<boolean>(false);

  useEffect(() => {
    // Keep a ref of the current sessionId to avoid stale closures in socket handlers
    sessionIdRef.current = sessionId;
  }, [sessionId]);

  useEffect(() => {
    const handleNewMessage = (data: MessageEvent) => {
      setMessages((prev) => [...prev, data]);
      // Any new message should clear typing indicator
      setIsAgentTyping(false);
      if (agentTypingTimerRef.current) window.clearTimeout(agentTypingTimerRef.current);
      agentTypingTimerRef.current = null;
    };

    socket.on('connect', () => setStatus('Connected'));
    socket.on('disconnect', (reason) => setStatus(`Disconnected: ${reason || 'unknown'}`));
    socket.on('reconnect', () => {
      setStatus('Reconnected');
      // Rejoin session as visitor if we already have identifiers
      const sId = sessionIdRef.current;
      if (sId && visitorId) {
        socket.emit('visitor_join', { sessionId: sId, visitorId }, () => {});
      }
    });
    socket.on('chat_started', (data: ChatEvent) => setSessionId(data.sessionId));
    socket.on('new_message', handleNewMessage);
    socket.on('agent_joined', () => setStatus('Agent has joined the chat'));
    socket.on('chat_closed', () => {
      setStatus('Chat has been closed');
      setIsClosed(true);
    });
    socket.on('user_typing', (data: { sessionId: string; role: 'USER' | 'AGENT' }) => {
      if (data.role === 'AGENT' && data.sessionId === sessionIdRef.current) {
        setIsAgentTyping(true);
        if (agentTypingTimerRef.current) window.clearTimeout(agentTypingTimerRef.current);
        agentTypingTimerRef.current = window.setTimeout(() => setIsAgentTyping(false), 3000) as unknown as number;
      }
    });
    socket.on('user_stop_typing', (data: { sessionId: string; role: 'USER' | 'AGENT' }) => {
      if (data.role === 'AGENT' && data.sessionId === sessionIdRef.current) {
        if (agentTypingTimerRef.current) window.clearTimeout(agentTypingTimerRef.current);
        setIsAgentTyping(false);
      }
    });

    return () => {
      socket.off('connect');
      socket.off('disconnect');
      socket.off('reconnect');
      socket.off('chat_started');
      socket.off('new_message', handleNewMessage);
      socket.off('agent_joined');
      socket.off('chat_closed');
      socket.off('user_typing');
      socket.off('user_stop_typing');
      if (agentTypingTimerRef.current) window.clearTimeout(agentTypingTimerRef.current);
      agentTypingTimerRef.current = null;
    };
  }, []);

  useEffect(() => {
    if (scrollAreaRef.current) {
      scrollAreaRef.current.scrollTop = scrollAreaRef.current.scrollHeight;
    }
  }, [messages]);

  // Request notifications only if not previously blocked/denied
  useEffect(() => {
    if (typeof window !== 'undefined' && 'Notification' in window) {
      if (Notification.permission === 'default') {
        Notification.requestPermission();
      }
    }
  }, []);

  useEffect(() => {
    if ('Notification' in window) {
      Notification.requestPermission();
    }
    socket.on('new_message_notification', (data) => {
      if (Notification.permission === 'granted') {
        new Notification('New Message Received', { body: data.content });
      }
    });
    socket.on('agent_joined_notification', () => {
      if (Notification.permission === 'granted') {
        new Notification('Agent has joined the chat');
      }
    });
    return () => {
      socket.off('new_message_notification');
      socket.off('agent_joined_notification');
    };
  }, []);

  // After pre-chat form submits session start
  const handleSessionStarted = (data: { sessionId: string; visitorId: string }) => {
    setSessionId(data.sessionId);
    setVisitorId(data.visitorId);
    setShowChat(true);
    setIsClosed(false);
    // Connect socket and join session as visitor
    socket.connect();
    socket.emit('visitor_join', { sessionId: data.sessionId, visitorId: data.visitorId }, (resp: any) => {
      if (resp.status === 'joined') {
        setStatus('Waiting for an agent');
        // Send an initial message so agents see context; delay slightly to ensure room join is processed
        setTimeout(() => {
          socket.emit('send_message', { sessionId: data.sessionId, role: 'USER', content: 'Hello, I need help.' });
        }, 100);
      } else {
        setStatus('Failed to join session');
      }
    });
  };

  const sendMessage = () => {
    if (sessionId && messageInput.trim()) {
      socket.emit('send_message', { sessionId, role: 'USER', content: messageInput });
      setMessageInput('');
    }
  };

  const exitChat = () => {
    if (!sessionId) return;
    socket.emit('end_chat', { sessionId });
  };

  const startNewChat = () => {
    // Reset to pre-chat form
    try { socket.disconnect(); } catch {}
    setMessages([]);
    setMessageInput('');
    setSessionId('');
    setVisitorId('');
    setIsAgentTyping(false);
    setIsClosed(false);
    setStatus('Disconnected');
    setShowChat(false);
  };

  return (
    <div className="fixed bottom-4 right-4">
      {!showChat ? (
        <PreChatForm onSessionStarted={handleSessionStarted} />
      ) : (
        <Card className="w-96 h-128 flex flex-col">
          <CardHeader className="flex flex-col gap-1">
            <div className="flex items-center justify-between">
              <CardTitle>Live Support</CardTitle>
              {sessionId && !isClosed && (
                <Button variant="secondary" size="sm" onClick={exitChat}>Exit Chat</Button>
              )}
            </div>
            <p className="text-sm text-gray-500">{status}</p>
          </CardHeader>
          <CardContent className="flex-1 p-0">
            <ScrollArea className="h-full p-4" ref={scrollAreaRef}>
              {messages.length === 0 && (
                <div className="flex flex-col items-center justify-center h-full">
                  <p className="text-sm text-muted-foreground">Waiting for an agent to join...</p>
                </div>
              )}
              {messages.map((msg, index) => (
                <div key={msg.id ?? `${msg.sessionId}-${msg.createdAt ?? 't'}-${index}`}
                     className={`mb-2 text-sm ${msg.role === 'USER' ? 'text-right' : 'text-left'}`}>
                  <div className={`inline-block p-2 rounded-lg ${msg.role === 'USER' ? 'bg-blue-500 text-white' : 'bg-gray-200 dark:bg-gray-700'}`}>
                    {msg.content}
                  </div>
                </div>
              ))}
              {isAgentTyping && <p className="text-sm italic">Agent is typing...</p>}
            </ScrollArea>
          </CardContent>
          {sessionId && !isClosed && (
            <CardFooter className="p-4 border-t">
              <div className="flex w-full space-x-2">
                <Input
                  placeholder="Type a message..."
                  value={messageInput}
                  onChange={(e) => {
                    setMessageInput(e.target.value);
                    if (e.target.value) {
                      socket.emit('typing', { sessionId, role: 'USER' });
                    } else {
                      socket.emit('stop_typing', { sessionId, role: 'USER' });
                    }
                  }}
                  onBlur={() => {
                    if (sessionId) socket.emit('stop_typing', { sessionId, role: 'USER' });
                  }}
                  onKeyPress={(e) => e.key === 'Enter' && sendMessage()}
                />
                <Button onClick={sendMessage}>Send</Button>
              </div>
            </CardFooter>
          )}
          {sessionId && isClosed && (
            <CardFooter className="p-4 border-t flex justify-between items-center">
              <span className="text-sm text-muted-foreground">This chat has ended.</span>
              <Button onClick={startNewChat} size="sm">Start New Chat</Button>
            </CardFooter>
          )}
        </Card>
      )}
    </div>
  );
}
