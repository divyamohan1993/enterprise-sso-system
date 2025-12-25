import { Module, Global } from '@nestjs/common';
import { RedisService } from './services/redis.service';
import { MetricsService } from './services/metrics.service';
import { WinstonLoggerService } from './services/winston-logger.service';
import { TracingService } from './services/tracing.service';

@Global()
@Module({
    providers: [
        RedisService,
        MetricsService,
        WinstonLoggerService,
        TracingService,
    ],
    exports: [
        RedisService,
        MetricsService,
        WinstonLoggerService,
        TracingService,
    ],
})
export class CommonModule { }
