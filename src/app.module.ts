import { Module, MiddlewareConsumer, NestModule } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { ThrottlerModule, ThrottlerGuard } from '@nestjs/throttler';
import { APP_GUARD, APP_FILTER } from '@nestjs/core';
import { AuthModule } from './auth/auth.module';
import { UsersModule } from './users/users.module';
import { BlockchainModule } from './blockchain/blockchain.module';
import { OauthModule } from './oauth/oauth.module';
import { HealthModule } from './health/health.module';
import { MetricsModule } from './metrics/metrics.module';
import { CommonModule } from './common/common.module';
import { envValidationSchema } from './common/config/env.validation';
import { GlobalExceptionFilter } from './common/filters/global-exception.filter';
import { CorrelationIdMiddleware } from './common/middleware/correlation-id.middleware';

@Module({
    imports: [
        // Configuration with validation
        ConfigModule.forRoot({
            isGlobal: true,
            validationSchema: envValidationSchema,
            validationOptions: {
                abortEarly: false, // Show all validation errors
            },
        }),

        // Rate limiting for DDoS protection
        ThrottlerModule.forRootAsync({
            imports: [ConfigModule],
            inject: [ConfigService],
            useFactory: (config: ConfigService) => ({
                throttlers: [
                    {
                        ttl: config.get<number>('THROTTLE_TTL') || 60000,
                        limit: config.get<number>('THROTTLE_LIMIT') || 100,
                    },
                ],
            }),
        }),

        // Common Module (Redis, shared services)
        CommonModule,

        // Feature Modules
        AuthModule,
        UsersModule,
        BlockchainModule,
        OauthModule,
        HealthModule,
        MetricsModule,
    ],
    controllers: [],
    providers: [
        // Global Rate Limiting Guard
        {
            provide: APP_GUARD,
            useClass: ThrottlerGuard,
        },
        // Global Exception Filter
        {
            provide: APP_FILTER,
            useClass: GlobalExceptionFilter,
        },
    ],
})
export class AppModule implements NestModule {
    configure(consumer: MiddlewareConsumer): void {
        // Apply correlation ID middleware to all routes
        consumer.apply(CorrelationIdMiddleware).forRoutes('*');
    }
}

