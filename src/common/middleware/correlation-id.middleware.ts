import { Injectable, NestMiddleware } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import { v4 as uuidv4 } from 'uuid';

declare global {
    namespace Express {
        interface Request {
            correlationId?: string;
        }
    }
}

/**
 * Correlation ID Middleware
 * 
 * Ensures every request has a unique correlation ID for distributed tracing.
 * - If X-Correlation-ID header exists, use it
 * - Otherwise, generate a new UUID v4
 * - Attach to request object and response headers
 */
@Injectable()
export class CorrelationIdMiddleware implements NestMiddleware {
    use(req: Request, res: Response, next: NextFunction): void {
        // Extract or generate correlation ID
        const correlationId =
            (req.headers['x-correlation-id'] as string) ||
            (req.headers['x-request-id'] as string) ||
            uuidv4();

        // Attach to request for use in handlers
        req.correlationId = correlationId;

        // Add to response headers
        res.setHeader('X-Correlation-ID', correlationId);

        next();
    }
}
