'use client';

import { useEffect, useMemo, useRef, useState } from 'react';
import type { BoardEventPayload } from '@board-app/shared';

export type BoardEvent = BoardEventPayload;

interface UseBoardEventsOptions {
  initialEvents?: BoardEvent[];
  endpoint?: string;
  workerBaseUrl?: string;
}

interface State {
  events: BoardEvent[];
  status: 'connecting' | 'connected' | 'disconnected' | 'error';
  error?: string;
}

export function useBoardEvents(
  boardId: string,
  { initialEvents = [], endpoint = '/boards', workerBaseUrl = 'http://localhost:8788' }: UseBoardEventsOptions = {}
): State {
  const [state, setState] = useState<State>({ events: initialEvents, status: 'connecting' });
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectAttempts = useRef(0);
  const reconnectTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const shouldReconnect = useRef(true);

  const wsUrl = useMemo(() => {
    const url = new URL(endpoint, workerBaseUrl);
    url.searchParams.set('boardId', boardId);
    return url.toString().replace('http', 'ws');
  }, [boardId, endpoint, workerBaseUrl]);

  useEffect(() => {
    let cancelled = false;
    const controller = new AbortController();

    async function hydrate() {
      try {
        const res = await fetch(`${workerBaseUrl}/boards/${encodeURIComponent(boardId)}/events?limit=50`, {
          signal: controller.signal
        });
        if (!res.ok) {
          throw new Error(`Failed to load events (${res.status})`);
        }
        const body = (await res.json()) as { events?: BoardEvent[] };
        if (!cancelled && body.events) {
          setState(prev => ({ ...prev, events: body.events.reverse() }));
        }
      } catch (error) {
        if (!cancelled) {
          if (error instanceof DOMException && error.name === 'AbortError') {
            return;
          }
          setState(prev => ({ ...prev, error: (error as Error).message }));
        }
      }
    }

    hydrate();

    return () => {
      cancelled = true;
      controller.abort();
    };
  }, [boardId, workerBaseUrl]);

  useEffect(() => {
    let isMounted = true;
    shouldReconnect.current = true;
    let socket: WebSocket | null = null;

    function cleanupSocket(closeCode?: number, closeReason?: string) {
      if (!socket) return;
      socket.removeEventListener('open', handleOpen);
      socket.removeEventListener('message', handleMessage);
      socket.removeEventListener('close', handleClose);
      socket.removeEventListener('error', handleError);
      socket.close(closeCode ?? 1000, closeReason ?? 'client navigating away');
      socket = null;
      wsRef.current = null;
    }

    const handleOpen = () => {
      reconnectAttempts.current = 0;
      if (!isMounted) return;
      setState(prev => ({ ...prev, status: 'connected', error: undefined }));
    };

    const handleMessage = (event: MessageEvent) => {
      try {
        const payload = JSON.parse(event.data);
        if (payload.type === 'ack') {
          return;
        }
        if (payload.type === 'keepalive') {
          return;
        }
        if (payload.type === 'event') {
          setState(prev => ({
            ...prev,
            events: [...prev.events, {
              id: payload.eventId ?? crypto.randomUUID(),
              event: payload.event ?? 'message',
              data: payload.data,
              timestamp: payload.timestamp ?? Date.now(),
              traceId: payload.trace_id ?? 'unknown'
            }]
          }));
        }
        if (payload.type === 'error') {
          setState(prev => ({ ...prev, error: payload.message ?? 'Unknown error' }));
        }
      } catch (error) {
        console.warn('[ui] failed to parse message', error);
      }
    };

    const scheduleReconnect = () => {
      if (!isMounted || !shouldReconnect.current) return;
      if (reconnectTimer.current) {
        clearTimeout(reconnectTimer.current);
        reconnectTimer.current = null;
      }
      const attempt = reconnectAttempts.current + 1;
      reconnectAttempts.current = attempt;
      const delay = Math.min(30_000, 1_000 * 2 ** Math.min(attempt, 5));
      reconnectTimer.current = setTimeout(() => {
        if (!isMounted || !shouldReconnect.current) return;
        setState(prev => ({ ...prev, status: 'connecting' }));
        reconnect();
      }, delay);
    };

    const handleClose = () => {
      if (!isMounted) return;
      setState(prev => ({ ...prev, status: 'disconnected' }));
      scheduleReconnect();
    };

    const handleError = (event: Event) => {
      console.error('[ui] websocket error', event);
      if (!isMounted) return;
      setState(prev => ({ ...prev, status: 'error', error: 'WebSocket error' }));
      scheduleReconnect();
    };

    const reconnect = () => {
      cleanupSocket();
      socket = new WebSocket(wsUrl);
      wsRef.current = socket;
      socket.addEventListener('open', handleOpen);
      socket.addEventListener('message', handleMessage);
      socket.addEventListener('close', handleClose);
      socket.addEventListener('error', handleError);
    };

    reconnect();

    return () => {
      isMounted = false;
      shouldReconnect.current = false;
      if (reconnectTimer.current) {
        clearTimeout(reconnectTimer.current);
        reconnectTimer.current = null;
      }
      cleanupSocket(1000, 'client navigating away');
      wsRef.current = null;
    };
  }, [wsUrl]);

  return state;
}
