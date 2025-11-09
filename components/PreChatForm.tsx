'use client';

import React, { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Textarea } from '@/components/ui/textarea';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Loader2, MessageCircle, AlertCircle, CheckCircle } from 'lucide-react';

interface PreChatFormProps {
  onSessionStarted?: (data: { sessionId: string; visitorId: string }) => void;
}

export default function PreChatForm({ onSessionStarted }: PreChatFormProps) {
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [issueType, setIssueType] = useState('');
  const [message, setMessage] = useState('');
  const [loading, setLoading] = useState(false);
  const [submitted, setSubmitted] = useState<'chat' | 'offline' | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [agentsOnline, setAgentsOnline] = useState<boolean | null>(null);

  // Check if any agents are online on mount
  React.useEffect(() => {
    fetch(`${process.env.NEXT_PUBLIC_BACKEND_URL}/agents/online`)
      .then(r => r.json())
      .then(({ online }) => setAgentsOnline(online))
      .catch(() => setAgentsOnline(false));
  }, []);

  const handleStartChat = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${process.env.NEXT_PUBLIC_BACKEND_URL}/sessions/start`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, email, issueType }),
      });
      if (!res.ok) throw new Error('Failed to start session');
      const data = await res.json();
      setSubmitted('chat');
      // Notify parent to transition to chat UI
      onSessionStarted?.({ sessionId: data.sessionId, visitorId: data.visitorId });
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
      const res = await fetch(`${process.env.NEXT_PUBLIC_BACKEND_URL}/offline/message`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, email, issueType, message }),
      });
      if (!res.ok) throw new Error('Failed to send offline message');
      const data = await res.json();
      setSubmitted('offline');
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
          <p className="text-sm text-muted-foreground">We've received your message and will respond as soon as possible.</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="w-full max-w-md mx-auto">
      <CardHeader className="text-center pb-2">
        <MessageCircle className="w-8 h-8 mx-auto mb-2 text-primary" />
        <CardTitle className="text-lg">
          {agentsOnline ? 'Start a Chat' : 'We\'re Offline'}
        </CardTitle>
        <CardDescription>
          {agentsOnline
            ? 'Fill in your details to start a live chat with an agent.'
            : 'Leave us a message and we\'ll get back to you.'}
        </CardDescription>
      </CardHeader>
      <form onSubmit={agentsOnline ? handleStartChat : handleOfflineMessage}>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 gap-4">
            <div>
              <Label htmlFor="name">Name</Label>
              <Input
                id="name"
                type="text"
                placeholder="Your name"
                value={name}
                onChange={e => setName(e.target.value)}
                required
                disabled={loading}
              />
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
            {!agentsOnline && (
              <div>
                <Label htmlFor="message">Message</Label>
                <Textarea
                  id="message"
                  placeholder="Describe your issue or question..."
                  value={message}
                  onChange={(e: React.ChangeEvent<HTMLTextAreaElement>) => setMessage(e.target.value)}
                  required
                  disabled={loading}
                  rows={4}
                />
              </div>
            )}
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
          <Button type="submit" className="w-full" disabled={loading}>
            {loading && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
            {agentsOnline ? 'Start Chat' : 'Send Message'}
          </Button>
        </CardFooter>
      </form>
    </Card>
  );
}
