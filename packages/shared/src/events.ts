export type EventType =
  | 'post.created'
  | 'post.reacted'
  | 'note'
  | 'message'
  | 'ping'
  | 'keepalive';

export interface SocketEvent<T = unknown> {
  type: EventType | string;
  eventId?: string;
  data: T;
  trace_id?: string;
  timestamp: number;
}
