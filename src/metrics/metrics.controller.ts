import { Controller, Get, Res } from '@nestjs/common';
import { Response } from 'express';
import { MetricsService } from '../common/services/metrics.service';

/**
 * Metrics Controller
 * 
 * Exposes Prometheus-compatible metrics endpoint
 */
@Controller('metrics')
export class MetricsController {
    constructor(private readonly metricsService: MetricsService) { }

    /**
     * Prometheus metrics endpoint
     * Compatible with Prometheus scraping
     */
    @Get()
    getPrometheusMetrics(@Res() res: Response): void {
        res.set('Content-Type', 'text/plain; version=0.0.4; charset=utf-8');
        res.send(this.metricsService.getPrometheusMetrics());
    }

    /**
     * JSON metrics endpoint
     * For dashboard consumption
     */
    @Get('json')
    getJsonMetrics(): object {
        return this.metricsService.getJsonMetrics();
    }
}
