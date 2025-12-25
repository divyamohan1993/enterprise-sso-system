import {
    ExceptionFilter,
    Catch,
    ArgumentsHost,
    HttpException,
    HttpStatus,
    Logger,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { v4 as uuidv4 } from 'uuid';

interface ErrorResponse {
    statusCode: number;
    timestamp: string;
    path: string;
    method: string;
    correlationId: string;
    error: {
        code: string;
        message: string;
        details?: any;
    };
}

@Catch()
export class GlobalExceptionFilter implements ExceptionFilter {
    private readonly logger = new Logger('ExceptionFilter');

    catch(exception: unknown, host: ArgumentsHost): void {
        const ctx = host.switchToHttp();
        const response = ctx.getResponse<Response>();
        const request = ctx.getRequest<Request>();

        // Get or generate correlation ID for request tracing
        const correlationId = (request.headers['x-correlation-id'] as string) || uuidv4();

        let statusCode: number;
        let errorCode: string;
        let message: string;
        let details: any = undefined;

        if (exception instanceof HttpException) {
            statusCode = exception.getStatus();
            const exceptionResponse = exception.getResponse();

            if (typeof exceptionResponse === 'string') {
                message = exceptionResponse;
                errorCode = this.getErrorCode(statusCode);
            } else if (typeof exceptionResponse === 'object') {
                const responseObj = exceptionResponse as any;
                message = responseObj.message || exception.message;
                errorCode = responseObj.error || this.getErrorCode(statusCode);
                details = responseObj.details || undefined;

                // Handle class-validator errors
                if (Array.isArray(responseObj.message)) {
                    details = { validationErrors: responseObj.message };
                    message = 'Validation failed';
                }
            } else {
                message = 'An error occurred';
                errorCode = 'UNKNOWN_ERROR';
            }
        } else if (exception instanceof Error) {
            statusCode = HttpStatus.INTERNAL_SERVER_ERROR;
            errorCode = 'INTERNAL_SERVER_ERROR';

            // Only expose error message in non-production
            if (process.env.NODE_ENV !== 'production') {
                message = exception.message;
                details = { stack: exception.stack };
            } else {
                message = 'An internal server error occurred';
            }
        } else {
            statusCode = HttpStatus.INTERNAL_SERVER_ERROR;
            errorCode = 'UNKNOWN_ERROR';
            message = 'An unexpected error occurred';
        }

        const errorResponse: ErrorResponse = {
            statusCode,
            timestamp: new Date().toISOString(),
            path: request.url,
            method: request.method,
            correlationId,
            error: {
                code: errorCode,
                message,
                ...(details && { details }),
            },
        };

        // Log the error with correlation ID for tracing
        this.logger.error(
            JSON.stringify({
                correlationId,
                statusCode,
                errorCode,
                message,
                path: request.url,
                method: request.method,
                userAgent: request.headers['user-agent'],
                ip: request.ip,
                ...(process.env.NODE_ENV !== 'production' && exception instanceof Error && {
                    stack: exception.stack
                }),
            }),
        );

        // Set security headers
        response.setHeader('X-Correlation-ID', correlationId);
        response.setHeader('X-Content-Type-Options', 'nosniff');

        response.status(statusCode).json(errorResponse);
    }

    private getErrorCode(statusCode: number): string {
        const errorCodes: Record<number, string> = {
            400: 'BAD_REQUEST',
            401: 'UNAUTHORIZED',
            403: 'FORBIDDEN',
            404: 'NOT_FOUND',
            405: 'METHOD_NOT_ALLOWED',
            409: 'CONFLICT',
            422: 'UNPROCESSABLE_ENTITY',
            429: 'TOO_MANY_REQUESTS',
            500: 'INTERNAL_SERVER_ERROR',
            502: 'BAD_GATEWAY',
            503: 'SERVICE_UNAVAILABLE',
        };
        return errorCodes[statusCode] || 'UNKNOWN_ERROR';
    }
}
