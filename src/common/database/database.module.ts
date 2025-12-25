import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule, ConfigService } from '@nestjs/config';

/**
 * Database Module
 * 
 * Provides TypeORM integration with MySQL
 * Falls back gracefully if database is not available
 */
@Module({
    imports: [
        TypeOrmModule.forRootAsync({
            imports: [ConfigModule],
            inject: [ConfigService],
            useFactory: (configService: ConfigService) => {
                const isProduction = configService.get('NODE_ENV') === 'production';
                const dbHost = configService.get<string>('DB_HOST');

                // If no DB host configured, skip database connection
                if (!dbHost) {
                    console.log('⚠️  Database not configured - using in-memory storage');
                    return {
                        type: 'sqlite',
                        database: ':memory:',
                        entities: [__dirname + '/../../**/*.entity{.ts,.js}'],
                        synchronize: true,
                    };
                }

                return {
                    type: 'mysql',
                    host: dbHost,
                    port: configService.get<number>('DB_PORT') || 3306,
                    username: configService.get<string>('DB_USER'),
                    password: configService.get<string>('DB_PASS'),
                    database: configService.get<string>('DB_NAME'),
                    entities: [__dirname + '/../../**/*.entity{.ts,.js}'],
                    synchronize: !isProduction,
                    logging: !isProduction,
                    ssl: configService.get<string>('DB_SSL') === 'true' ? {
                        rejectUnauthorized: true,
                    } : undefined,
                };
            },
        }),
    ],
    exports: [TypeOrmModule],
})
export class DatabaseModule { }
