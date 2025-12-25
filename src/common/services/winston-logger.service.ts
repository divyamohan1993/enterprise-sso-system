import { Injectable, LoggerService, Scope } from '@nestjs/common';
import * as winston from 'winston';

/**
 * Winston Logger Service
 * 
 * Enterprise-grade structured JSON logging with:
 * - Correlation ID tracking
 * - Log levels (error, warn, info, debug, verbose)
 * - JSON format for production
 * - Pretty format for development
 * - Log rotation ready
 */
@Injectable({ scope: Scope.TRANSIENT })
export class WinstonLoggerService implements LoggerService {
    private readonly logger: winston.Logger;
    private context?: string;
    private correlationId?: string;

    constructor() {
        const isProduction = process.env.NODE_ENV === 'production';

        // Define log format
        const jsonFormat = winston.format.combine(
            winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss.SSS' }),
            winston.format.errors({ stack: true }),
            winston.format.json(),
        );

        const prettyFormat = winston.format.combine(
            winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss.SSS' }),
            winston.format.errors({ stack: true }),
            winston.format.colorize(),
            winston.format.printf(({ timestamp, level, message, context, correlationId, ...rest }) => {
                const ctx = context ? `[${context}]` : '';
                const cid = correlationId ? `(${correlationId})` : '';
                const extra = Object.keys(rest).length > 0 ? ` ${JSON.stringify(rest)}` : '';
                return `${timestamp} ${level} ${ctx}${cid} ${message}${extra}`;
            }),
        );

        this.logger = winston.createLogger({
            level: isProduction ? 'info' : 'debug',
            format: isProduction ? jsonFormat : prettyFormat,
            defaultMeta: {
                service: 'enterprise-sso',
                version: '1.0.0',
            },
            transports: [
                new winston.transports.Console(),
            ],
        });

        // Add file transport in production
        if (isProduction) {
            this.logger.add(new winston.transports.File({
                filename: 'logs/error.log',
                level: 'error',
                maxsize: 10 * 1024 * 1024, // 10MB
                maxFiles: 5,
            }));
            this.logger.add(new winston.transports.File({
                filename: 'logs/combined.log',
                maxsize: 10 * 1024 * 1024,
                maxFiles: 10,
            }));
        }
    }

    setContext(context: string): this {
        this.context = context;
        return this;
    }

    setCorrelationId(correlationId: string): this {
        this.correlationId = correlationId;
        return this;
    }

    private formatMessage(message: unknown): string {
        if (typeof message === 'string') return message;
        if (message instanceof Error) return message.message;
        return JSON.stringify(message);
    }

    private getMeta(optionalParams: unknown[]): Record<string, unknown> {
        const meta: Record<string, unknown> = {
            context: this.context,
            correlationId: this.correlationId,
        };

        if (optionalParams.length > 0) {
            if (typeof optionalParams[0] === 'string') {
                meta.context = optionalParams[0];
            } else if (typeof optionalParams[0] === 'object') {
                Object.assign(meta, optionalParams[0]);
            }
        }

        return meta;
    }

    log(message: unknown, ...optionalParams: unknown[]): void {
        this.logger.info(this.formatMessage(message), this.getMeta(optionalParams));
    }

    error(message: unknown, trace?: string, ...optionalParams: unknown[]): void {
        const meta = this.getMeta(optionalParams);
        if (trace) {
            meta.stack = trace;
        }
        this.logger.error(this.formatMessage(message), meta);
    }

    warn(message: unknown, ...optionalParams: unknown[]): void {
        this.logger.warn(this.formatMessage(message), this.getMeta(optionalParams));
    }

    debug(message: unknown, ...optionalParams: unknown[]): void {
        this.logger.debug(this.formatMessage(message), this.getMeta(optionalParams));
    }

    verbose(message: unknown, ...optionalParams: unknown[]): void {
        this.logger.verbose(this.formatMessage(message), this.getMeta(optionalParams));
    }

    // Structured logging methods for specific events
    logAuth(event: string, userId?: string, success?: boolean, details?: Record<string, unknown>): void {
        this.logger.info('AUTH_EVENT', {
            context: 'AuthService',
            correlationId: this.correlationId,
            event,
            userId,
            success,
            ...details,
        });
    }

    logSecurity(event: string, severity: 'low' | 'medium' | 'high' | 'critical', details?: Record<string, unknown>): void {
        const level = severity === 'critical' || severity === 'high' ? 'error' :
            severity === 'medium' ? 'warn' : 'info';

        this.logger[level]('SECURITY_EVENT', {
            context: 'Security',
            correlationId: this.correlationId,
            event,
            severity,
            ...details,
        });
    }

    logRequest(method: string, path: string, statusCode: number, durationMs: number, ip?: string): void {
        const level = statusCode >= 500 ? 'error' : statusCode >= 400 ? 'warn' : 'info';

        this.logger[level]('HTTP_REQUEST', {
            context: 'HTTP',
            correlationId: this.correlationId,
            method,
            path,
            statusCode,
            durationMs,
            ip,
        });
    }
}
