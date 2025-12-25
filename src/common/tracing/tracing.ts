import { NodeSDK } from '@opentelemetry/sdk-node';
import { getNodeAutoInstrumentations } from '@opentelemetry/auto-instrumentations-node';
import { OTLPTraceExporter } from '@opentelemetry/exporter-trace-otlp-http';
import { resourceFromAttributes } from '@opentelemetry/resources';
import { ATTR_SERVICE_NAME, ATTR_SERVICE_VERSION } from '@opentelemetry/semantic-conventions';
import { SimpleSpanProcessor, ConsoleSpanExporter, BatchSpanProcessor, SpanProcessor } from '@opentelemetry/sdk-trace-node';

/**
 * OpenTelemetry Tracing Configuration
 * 
 * Provides distributed tracing with:
 * - Automatic HTTP instrumentation
 * - Express middleware instrumentation
 * - OTLP export to collectors (Jaeger, Zipkin, etc.)
 * - Console export for development
 */
export function initTracing(): NodeSDK | null {
    const isProduction = process.env.NODE_ENV === 'production';
    const otlpEndpoint = process.env.OTEL_EXPORTER_OTLP_ENDPOINT;
    const tracingEnabled = process.env.TRACING_ENABLED === 'true';

    if (!tracingEnabled) {
        console.log('📊 OpenTelemetry tracing disabled');
        return null;
    }

    console.log('📊 Initializing OpenTelemetry tracing...');

    // Create resource with service info
    const resource = resourceFromAttributes({
        [ATTR_SERVICE_NAME]: 'enterprise-sso',
        [ATTR_SERVICE_VERSION]: '1.0.0',
        'deployment.environment': process.env.NODE_ENV || 'development',
    });

    // Configure exporters
    const spanProcessors: SpanProcessor[] = [];

    if (otlpEndpoint) {
        // Production: Export to OTLP collector
        const otlpExporter = new OTLPTraceExporter({
            url: `${otlpEndpoint}/v1/traces`,
        });
        spanProcessors.push(new BatchSpanProcessor(otlpExporter));
        console.log(`📊 OTLP exporter configured: ${otlpEndpoint}`);
    }

    if (!isProduction) {
        // Development: Console output
        spanProcessors.push(new SimpleSpanProcessor(new ConsoleSpanExporter()));
    }

    // Create SDK
    const sdk = new NodeSDK({
        resource,
        spanProcessors,
        instrumentations: [getNodeAutoInstrumentations()],
    });

    // Start SDK
    sdk.start();
    console.log('📊 OpenTelemetry tracing started');

    // Graceful shutdown
    process.on('SIGTERM', () => {
        sdk.shutdown()
            .then(() => console.log('📊 OpenTelemetry shut down'))
            .catch((err) => console.error('📊 OpenTelemetry shutdown error', err));
    });

    return sdk;
}
