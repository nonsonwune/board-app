// Structured logging utility for production observability

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

export interface LogContext {
    traceId?: string;
    userId?: string;
    boardId?: string;
    postId?: string;
    [key: string]: unknown;
}

class Logger {
    constructor(private context: LogContext = {}) { }

    private log(level: LogLevel, message: string, data?: Record<string, unknown>) {
        const logEntry = {
            level,
            message,
            timestamp: new Date().toISOString(),
            ...this.context,
            ...data
        };
        console.log(JSON.stringify(logEntry));
    }

    debug(message: string, data?: Record<string, unknown>) {
        this.log('debug', message, data);
    }

    info(message: string, data?: Record<string, unknown>) {
        this.log('info', message, data);
    }

    warn(message: string, data?: Record<string, unknown>) {
        this.log('warn', message, data);
    }

    error(message: string, error?: Error | unknown, data?: Record<string, unknown>) {
        const errorData = error instanceof Error
            ? { error: error.message, stack: error.stack, ...data }
            : { error: String(error), ...data };
        this.log('error', message, errorData);
    }

    withContext(additionalContext: LogContext): Logger {
        return new Logger({ ...this.context, ...additionalContext });
    }
}

// Global logger instance
export const logger = new Logger();

// Create logger with request context
export function createRequestLogger(request: Request, traceId?: string): Logger {
    const url = new URL(request.url);
    return logger.withContext({
        traceId: traceId ?? crypto.randomUUID(),
        method: request.method,
        path: url.pathname,
        userAgent: request.headers.get('User-Agent') || undefined
    });
}
