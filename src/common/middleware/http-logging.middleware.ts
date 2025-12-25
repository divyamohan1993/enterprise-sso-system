import { Injectable, NestMiddleware, Logger } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import { MetricsService } from '../services/metrics.service';

/**
 * HTTP Logging Middleware
 * 
 * Logs all HTTP requests with:
 * - Method, path, status code
 * - Response time
 * - User agent and IP
 * - Correlation ID
 */
@Injectable()
export class HttpLoggingMiddleware implements NestMiddleware {
    private readonly logger = new Logger('HTTP');

    constructor(private readonly metricsService: MetricsService) { }

    use(req: Request, res: Response, next: NextFunction): void {
        const startTime = Date.now();
        const { method, originalUrl, ip } = req;
        const userAgent = req.get('user-agent') || '';
        const correlationId = req.headers['x-correlation-id'] as string || '';

        // Log request start (debug level)
        this.logger.debug(`→ ${method} ${originalUrl}`, {
            ip,
            userAgent: userAgent.substring(0, 100),
            correlationId,
        });

        // Capture response
        res.on('finish', () => {
            const duration = Date.now() - startTime;
            const { statusCode } = res;

            // Log based on status code
            const logMethod = statusCode >= 500 ? 'error' :
                statusCode >= 400 ? 'warn' : 'log';

            this.logger[logMethod](
                `← ${method} ${originalUrl} ${statusCode} ${duration}ms`,
                correlationId ? `(${correlationId})` : '',
            );

            // Record metrics
            this.metricsService.recordHttpRequest(method, originalUrl, statusCode, duration);
        });

        next();
    }
}
