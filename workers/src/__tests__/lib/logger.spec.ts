import { describe, expect, it, vi } from 'vitest';
import { logger, createRequestLogger } from '../../lib/logger';

describe('Logger', () => {
    describe('logger.info', () => {
        it('should log JSON with correct structure', () => {
            const consoleSpy = vi.spyOn(console, 'log');

            logger.info('Test message', { key: 'value' });

            expect(consoleSpy).toHaveBeenCalled();
            const loggedData = JSON.parse(consoleSpy.mock.calls[0][0]);

            expect(loggedData).toHaveProperty('level', 'info');
            expect(loggedData).toHaveProperty('message', 'Test message');
            expect(loggedData).toHaveProperty('key', 'value');
            expect(loggedData).toHaveProperty('timestamp');

            consoleSpy.mockRestore();
        });
    });

    describe('logger.error', () => {
        it('should log errors with stack trace', () => {
            const consoleSpy = vi.spyOn(console, 'log');
            const testError = new Error('Test error');

            logger.error('Error occurred', testError);

            expect(consoleSpy).toHaveBeenCalled();
            const loggedData = JSON.parse(consoleSpy.mock.calls[0][0]);

            expect(loggedData).toHaveProperty('level', 'error');
            expect(loggedData).toHaveProperty('message', 'Error occurred');
            expect(loggedData).toHaveProperty('error', 'Test error');
            expect(loggedData).toHaveProperty('stack');

            consoleSpy.mockRestore();
        });
    });

    describe('logger.withContext', () => {
        it('should create new logger with additional context', () => {
            const consoleSpy = vi.spyOn(console, 'log');
            const contextLogger = logger.withContext({ userId: 'user-123' });

            contextLogger.info('User action', { action: 'login' });

            const loggedData = JSON.parse(consoleSpy.mock.calls[0][0]);

            expect(loggedData).toHaveProperty('userId', 'user-123');
            expect(loggedData).toHaveProperty('action', 'login');

            consoleSpy.mockRestore();
        });
    });

    describe('createRequestLogger', () => {
        it('should create logger with request context', () => {
            const consoleSpy = vi.spyOn(console, 'log');
            const request = new Request('http://localhost/api/test', {
                method: 'POST',
                headers: { 'User-Agent': 'test-agent' }
            });

            const requestLogger = createRequestLogger(request, 'trace-123');
            requestLogger.info('Request received');

            const loggedData = JSON.parse(consoleSpy.mock.calls[0][0]);

            expect(loggedData).toHaveProperty('traceId', 'trace-123');
            expect(loggedData).toHaveProperty('method', 'POST');
            expect(loggedData).toHaveProperty('path', '/api/test');
            expect(loggedData).toHaveProperty('userAgent', 'test-agent');

            consoleSpy.mockRestore();
        });
    });

    describe('log levels', () => {
        it('should support all log levels', () => {
            const consoleSpy = vi.spyOn(console, 'log');

            logger.debug('Debug message');
            logger.info('Info message');
            logger.warn('Warn message');
            logger.error('Error message');

            expect(consoleSpy).toHaveBeenCalledTimes(4);

            const levels = consoleSpy.mock.calls.map(call => {
                const data = JSON.parse(call[0]);
                return data.level;
            });

            expect(levels).toEqual(['debug', 'info', 'warn', 'error']);

            consoleSpy.mockRestore();
        });
    });
});
