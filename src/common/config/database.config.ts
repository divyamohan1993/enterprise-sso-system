import { DataSourceOptions } from 'typeorm';

/**
 * TypeORM Database Configuration
 * 
 * Supports MySQL/MariaDB with:
 * - Connection pooling
 * - SSL in production
 * - Automatic migrations
 */
export const getDatabaseConfig = (): DataSourceOptions => {
    const isProduction = process.env.NODE_ENV === 'production';

    return {
        type: 'mysql',
        host: process.env.DB_HOST || 'localhost',
        port: parseInt(process.env.DB_PORT || '3306', 10),
        username: process.env.DB_USER || 'sso_admin',
        password: process.env.DB_PASS || '',
        database: process.env.DB_NAME || 'sso_db',
        entities: [__dirname + '/../../**/*.entity{.ts,.js}'],
        synchronize: !isProduction, // Auto-sync in dev only
        logging: !isProduction,

        // Connection pool settings
        extra: {
            connectionLimit: 10,
            waitForConnections: true,
            queueLimit: 0,
        },

        // SSL configuration for production
        ssl: process.env.DB_SSL === 'true' ? {
            rejectUnauthorized: true,
        } : undefined,
    };
};
