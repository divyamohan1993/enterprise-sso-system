import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { trace, Span, SpanStatusCode, context, SpanKind } from '@opentelemetry/api';

/**
 * Tracing Service
 * 
 * Provides OpenTelemetry tracing utilities:
 * - Custom span creation
 * - Context propagation
 * - Error recording
 * - Attribute injection
 */
@Injectable()
export class TracingService implements OnModuleInit {
    private readonly logger = new Logger(TracingService.name);
    private tracer = trace.getTracer('enterprise-sso', '1.0.0');

    async onModuleInit(): Promise<void> {
        this.logger.log('📊 Tracing service initialized');
    }

    /**
     * Create a custom span for tracking operations
     */
    startSpan(name: string, kind: SpanKind = SpanKind.INTERNAL): Span {
        return this.tracer.startSpan(name, { kind });
    }

    /**
     * Execute a function within a traced span
     */
    async trace<T>(
        name: string,
        fn: (span: Span) => Promise<T>,
        attributes?: Record<string, string | number | boolean>
    ): Promise<T> {
        const span = this.startSpan(name);

        if (attributes) {
            span.setAttributes(attributes);
        }

        try {
            const result = await context.with(trace.setSpan(context.active(), span), () => fn(span));
            span.setStatus({ code: SpanStatusCode.OK });
            return result;
        } catch (error) {
            span.setStatus({
                code: SpanStatusCode.ERROR,
                message: error instanceof Error ? error.message : 'Unknown error',
            });
            span.recordException(error instanceof Error ? error : new Error(String(error)));
            throw error;
        } finally {
            span.end();
        }
    }

    /**
     * Add authentication event tracing
     */
    traceAuthEvent(event: string, userId?: string, success?: boolean): Span {
        const span = this.startSpan(`auth.${event}`, SpanKind.INTERNAL);
        span.setAttributes({
            'auth.event': event,
            'auth.success': success ?? true,
        });
        if (userId) {
            span.setAttribute('user.id', userId);
        }
        return span;
    }

    /**
     * Add blockchain operation tracing
     */
    traceBlockchainOp(operation: string, blockIndex?: number): Span {
        const span = this.startSpan(`blockchain.${operation}`, SpanKind.INTERNAL);
        span.setAttributes({
            'blockchain.operation': operation,
        });
        if (blockIndex !== undefined) {
            span.setAttribute('blockchain.block_index', blockIndex);
        }
        return span;
    }

    /**
     * Get current trace ID for correlation
     */
    getCurrentTraceId(): string | undefined {
        const span = trace.getActiveSpan();
        return span?.spanContext().traceId;
    }

    /**
     * Get current span ID
     */
    getCurrentSpanId(): string | undefined {
        const span = trace.getActiveSpan();
        return span?.spanContext().spanId;
    }
}
