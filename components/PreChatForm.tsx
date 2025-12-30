'use client';

import React, { useState, useCallback } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Textarea } from '@/components/ui/textarea';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Loader2, MessageCircle, AlertCircle, CheckCircle } from 'lucide-react';

const BACKEND_URL = process.env.NEXT_PUBLIC_BACKEND_URL || 'http://localhost:3010';

interface PreChatFormProps {
  onSessionStarted: (data: { sessionId: string; visitorId: string; initialMessage?: string }) => void;
}

export default function PreChatForm({ onSessionStarted }: PreChatFormProps) {
  const [firstName, setFirstName] = useState('');
  const [lastName, setLastName] = useState('');
  const [email, setEmail] = useState('');
  const [issueType, setIssueType] = useState('');
  const [message, setMessage] = useState('');
  const [loading, setLoading] = useState(false);
  const [submitted, setSubmitted] = useState<'chat' | 'offline' | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [agentsOnline, setAgentsOnline] = useState<boolean | null>(null);
  const [agentsCount, setAgentsCount] = useState<number>(0);
  const [checkingAgents, setCheckingAgents] = useState<boolean>(false);
  const [lastCheckedAt, setLastCheckedAt] = useState<number | null>(null);

  const checkAgentsOnline = useCallback(async () => {
    setCheckingAgents(true);
    try {
      const res = await fetch(`${BACKEND_URL}/agents/online`);
      if (!res.ok) throw new Error('Failed');
      const data = await res.json();
      setAgentsOnline(Boolean(data?.online));
      setAgentsCount(typeof data?.count === 'number' ? data.count : data?.online ? 1 : 0);
      setLastCheckedAt(Date.now());
    } catch {
      setAgentsOnline(false);
    } finally {
      setCheckingAgents(false);
    }
  }, []);

  // Initial check and periodic polling
  React.useEffect(() => {
    checkAgentsOnline();
    const id = window.setInterval(checkAgentsOnline, 15000);
    return () => window.clearInterval(id);
  }, [checkAgentsOnline]);

  const handleStartChat = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${BACKEND_URL}/sessions`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          firstName,
          lastName,
          email,
          issueType,
          message: message.trim() || undefined,
        }),
      });
      if (!res.ok) throw new Error('Failed to start session');
      const data = await res.json();
      setSubmitted('chat');
      onSessionStarted({
        sessionId: data.session?.id ?? data.sessionId,
        visitorId: data.visitorId,
        initialMessage: message.trim() ? message.trim() : undefined,
      });
      setMessage('');
    } catch (err) {
      setError('Unable to start chat. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleOfflineMessage = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${BACKEND_URL}/offline/message`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ firstName, lastName, email, issueType, message }),
      });
      if (!res.ok) throw new Error('Failed to send offline message');
      const data = await res.json();
      setSubmitted('offline');
      setMessage('');
    } catch (err) {
      setError('Unable to send message. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  if (agentsOnline === null) {
    return (
      <Card className="w-full max-w-md mx-auto">
        <CardHeader className="text-center pb-2">
          <MessageCircle className="w-8 h-8 mx-auto mb-2 text-primary" />
          <CardTitle className="text-lg">Loading...</CardTitle>
        </CardHeader>
        <CardContent className="flex justify-center pb-4">
          <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
        </CardContent>
      </Card>
    );
  }

  if (submitted === 'chat') {
    return (
      <Card className="w-full max-w-md mx-auto">
        <CardHeader className="text-center pb-2">
          <CheckCircle className="w-8 h-8 mx-auto mb-2 text-green-600" />
          <CardTitle className="text-lg">Chat Started</CardTitle>
          <CardDescription>An agent will be with you shortly.</CardDescription>
        </CardHeader>
        <CardContent className="text-center">
          <p className="text-sm text-muted-foreground">Please wait while we connect you to an available agent.</p>
        </CardContent>
      </Card>
    );
  }

  if (submitted === 'offline') {
    return (
      <Card className="w-full max-w-md mx-auto">
        <CardHeader className="text-center pb-2">
          <CheckCircle className="w-8 h-8 mx-auto mb-2 text-green-600" />
          <CardTitle className="text-lg">Message Received</CardTitle>
          <CardDescription>We'll get back to you soon.</CardDescription>
        </CardHeader>
        <CardContent className="text-center">
          <p className="text-sm text-muted-foreground">
            We've received your message and will respond as soon as possible.
          </p>
          <Button className="mt-4" variant="outline" onClick={() => { setSubmitted(null); checkAgentsOnline(); }}>
            Send another message
          </Button>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="w-full max-w-md mx-auto">
      <CardHeader className="text-center pb-2">
        <MessageCircle className="w-8 h-8 mx-auto mb-2 text-primary" />
        <CardTitle className="text-lg">Start a Chat</CardTitle>
        <CardDescription>
          Fill in your details to start a chat. Our bot will assist you first, and an agent will join if needed.
        </CardDescription>
        <div className="mt-2 flex items-center justify-center gap-2 text-xs text-muted-foreground">
          <span>{checkingAgents ? 'Checking availability…' : `Last checked ${lastCheckedAt ? new Date(lastCheckedAt).toLocaleTimeString() : 'just now'}`}</span>
          <Button variant="ghost" size="sm" onClick={checkAgentsOnline} disabled={checkingAgents}>
            {checkingAgents && <Loader2 className="mr-1 h-3 w-3 animate-spin" />}Refresh
          </Button>
        </div>
      </CardHeader>
      <form onSubmit={handleStartChat}>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 gap-4">
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <div>
                <Label htmlFor="firstName">First name (optional)</Label>
                <Input
                  id="firstName"
                  type="text"
                  placeholder="First name"
                  value={firstName}
                  onChange={e => setFirstName(e.target.value)}
                  disabled={loading}
                />
              </div>
              <div>
                <Label htmlFor="lastName">Last name (optional)</Label>
                <Input
                  id="lastName"
                  type="text"
                  placeholder="Last name"
                  value={lastName}
                  onChange={e => setLastName(e.target.value)}
                  disabled={loading}
                />
              </div>
            </div>
            <div>
              <Label htmlFor="email">Email</Label>
              <Input
                id="email"
                type="email"
                placeholder="your@email.com"
                value={email}
                onChange={e => setEmail(e.target.value)}
                required
                disabled={loading}
              />
            </div>
            <div>
              <Label htmlFor="issueType">Issue Type</Label>
              <Select value={issueType} onValueChange={setIssueType} disabled={loading}>
                <SelectTrigger>
                  <SelectValue placeholder="Select an issue type" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="general">General Inquiry</SelectItem>
                  <SelectItem value="technical">Technical Support</SelectItem>
                  <SelectItem value="billing">Billing</SelectItem>
                  <SelectItem value="feedback">Feedback</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label htmlFor="message">How can we help? (optional)</Label>
              <Textarea
                id="message"
                placeholder="Share the details so our team can jump in prepared."
                value={message}
                onChange={(e: React.ChangeEvent<HTMLTextAreaElement>) => setMessage(e.target.value)}
                disabled={loading}
                rows={4}
                maxLength={1000}
              />
              <div className="mt-1 flex justify-between text-[10px] text-muted-foreground">
                <span>
                  Optional but helpful—our bot will assist you.
                </span>
                <span>{message.length}/1000</span>
              </div>
            </div>
          </div>
          {error && (
            <Alert variant="destructive">
              <AlertCircle className="h-4 w-4" />
              <AlertTitle>Error</AlertTitle>
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}
        </CardContent>
        <CardFooter>
          <Button
            type="submit"
            className="w-full"
            disabled={loading}
          >
            {loading && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
            Start Chat
          </Button>
        </CardFooter>
      </form>
    </Card>
  );
}
