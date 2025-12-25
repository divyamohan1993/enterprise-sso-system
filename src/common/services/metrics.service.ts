import { Injectable, OnModuleInit, Logger } from '@nestjs/common';

/**
 * Prometheus Metrics Service
 * 
 * Exposes application metrics for monitoring:
 * - HTTP request duration
 * - Authentication events
 * - Blockchain operations
 * - System health
 */
@Injectable()
export class MetricsService implements OnModuleInit {
    private readonly logger = new Logger(MetricsService.name);

    // Metric counters (in-memory, can be exported to Prometheus)
    private metrics: {
        httpRequestsTotal: Map<string, number>;
        httpRequestDuration: Map<string, number[]>;
        authEventsTotal: Map<string, number>;
        mfaEventsTotal: Map<string, number>;
        blockchainBlocksTotal: number;
        activeSessionsGauge: number;
    };

    constructor() {
        this.metrics = {
            httpRequestsTotal: new Map(),
            httpRequestDuration: new Map(),
            authEventsTotal: new Map(),
            mfaEventsTotal: new Map(),
            blockchainBlocksTotal: 0,
            activeSessionsGauge: 0,
        };
    }

    async onModuleInit(): Promise<void> {
        this.logger.log('📊 Metrics service initialized');
    }

    // ========================================
    // HTTP METRICS
    // ========================================

    recordHttpRequest(method: string, path: string, statusCode: number, durationMs: number): void {
        const key = `${method}:${path}:${statusCode}`;

        // Increment counter
        const current = this.metrics.httpRequestsTotal.get(key) || 0;
        this.metrics.httpRequestsTotal.set(key, current + 1);

        // Record duration
        const durations = this.metrics.httpRequestDuration.get(key) || [];
        durations.push(durationMs);
        // Keep only last 1000 samples
        if (durations.length > 1000) {
            durations.shift();
        }
        this.metrics.httpRequestDuration.set(key, durations);
    }

    // ========================================
    // AUTHENTICATION METRICS
    // ========================================

    recordAuthEvent(event: 'login_success' | 'login_failure' | 'logout' | 'token_refresh' | 'password_change'): void {
        const current = this.metrics.authEventsTotal.get(event) || 0;
        this.metrics.authEventsTotal.set(event, current + 1);
    }

    recordMfaEvent(event: 'setup' | 'verify_success' | 'verify_failure' | 'backup_used'): void {
        const current = this.metrics.mfaEventsTotal.get(event) || 0;
        this.metrics.mfaEventsTotal.set(event, current + 1);
    }

    // ========================================
    // BLOCKCHAIN METRICS
    // ========================================

    recordBlockchainBlock(): void {
        this.metrics.blockchainBlocksTotal++;
    }

    // ========================================
    // SESSION METRICS
    // ========================================

    setActiveSessions(count: number): void {
        this.metrics.activeSessionsGauge = count;
    }

    incrementActiveSessions(): void {
        this.metrics.activeSessionsGauge++;
    }

    decrementActiveSessions(): void {
        if (this.metrics.activeSessionsGauge > 0) {
            this.metrics.activeSessionsGauge--;
        }
    }

    // ========================================
    // PROMETHEUS FORMAT EXPORT
    // ========================================

    /**
     * Export metrics in Prometheus format
     */
    getPrometheusMetrics(): string {
        const lines: string[] = [];

        // HTTP Requests Total
        lines.push('# HELP http_requests_total Total number of HTTP requests');
        lines.push('# TYPE http_requests_total counter');
        for (const [key, value] of this.metrics.httpRequestsTotal) {
            const [method, path, status] = key.split(':');
            lines.push(`http_requests_total{method="${method}",path="${path}",status="${status}"} ${value}`);
        }

        // HTTP Request Duration
        lines.push('# HELP http_request_duration_seconds HTTP request duration in seconds');
        lines.push('# TYPE http_request_duration_seconds histogram');
        for (const [key, durations] of this.metrics.httpRequestDuration) {
            const [method, path] = key.split(':');
            if (durations.length > 0) {
                const sum = durations.reduce((a, b) => a + b, 0) / 1000; // Convert to seconds
                const count = durations.length;
                lines.push(`http_request_duration_seconds_sum{method="${method}",path="${path}"} ${sum.toFixed(4)}`);
                lines.push(`http_request_duration_seconds_count{method="${method}",path="${path}"} ${count}`);
            }
        }

        // Auth Events
        lines.push('# HELP auth_events_total Total number of authentication events');
        lines.push('# TYPE auth_events_total counter');
        for (const [event, value] of this.metrics.authEventsTotal) {
            lines.push(`auth_events_total{event="${event}"} ${value}`);
        }

        // MFA Events
        lines.push('# HELP mfa_events_total Total number of MFA events');
        lines.push('# TYPE mfa_events_total counter');
        for (const [event, value] of this.metrics.mfaEventsTotal) {
            lines.push(`mfa_events_total{event="${event}"} ${value}`);
        }

        // Blockchain Blocks
        lines.push('# HELP blockchain_blocks_total Total number of blockchain blocks');
        lines.push('# TYPE blockchain_blocks_total counter');
        lines.push(`blockchain_blocks_total ${this.metrics.blockchainBlocksTotal}`);

        // Active Sessions
        lines.push('# HELP active_sessions_current Current number of active sessions');
        lines.push('# TYPE active_sessions_current gauge');
        lines.push(`active_sessions_current ${this.metrics.activeSessionsGauge}`);

        // System Info
        lines.push('# HELP sso_system_info SSO System information');
        lines.push('# TYPE sso_system_info gauge');
        lines.push(`sso_system_info{version="1.0.0",node="${process.version}"} 1`);

        return lines.join('\n');
    }

    /**
     * Get metrics as JSON for API consumption
     */
    getJsonMetrics(): object {
        return {
            http: {
                requestsTotal: Object.fromEntries(this.metrics.httpRequestsTotal),
                requestDuration: Object.fromEntries(
                    Array.from(this.metrics.httpRequestDuration.entries()).map(([key, values]) => {
                        const sum = values.reduce((a, b) => a + b, 0);
                        return [key, {
                            count: values.length,
                            sum: sum,
                            avg: values.length > 0 ? sum / values.length : 0,
                            min: values.length > 0 ? Math.min(...values) : 0,
                            max: values.length > 0 ? Math.max(...values) : 0,
                        }];
                    })
                ),
            },
            auth: Object.fromEntries(this.metrics.authEventsTotal),
            mfa: Object.fromEntries(this.metrics.mfaEventsTotal),
            blockchain: {
                blocksTotal: this.metrics.blockchainBlocksTotal,
            },
            sessions: {
                active: this.metrics.activeSessionsGauge,
            },
            system: {
                version: '1.0.0',
                node: process.version,
                uptime: process.uptime(),
                memory: process.memoryUsage(),
            },
        };
    }

    /**
     * Reset all metrics (for testing)
     */
    reset(): void {
        this.metrics.httpRequestsTotal.clear();
        this.metrics.httpRequestDuration.clear();
        this.metrics.authEventsTotal.clear();
        this.metrics.mfaEventsTotal.clear();
        this.metrics.blockchainBlocksTotal = 0;
        this.metrics.activeSessionsGauge = 0;
    }
}
