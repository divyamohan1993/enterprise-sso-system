import * as Joi from 'joi';

/**
 * Enterprise-grade environment validation schema
 * All sensitive configuration must be validated at startup
 */
export const envValidationSchema = Joi.object({
    // Application
    NODE_ENV: Joi.string()
        .valid('development', 'production', 'test', 'staging')
        .default('development'),
    PORT: Joi.number().port().default(3000),
    HOST: Joi.string().hostname().default('0.0.0.0'),
    API_PREFIX: Joi.string().optional(),

    // Database
    DB_HOST: Joi.string().required(),
    DB_PORT: Joi.number().port().default(3306),
    DB_USER: Joi.string().required(),
    DB_PASS: Joi.string().required(),
    DB_NAME: Joi.string().required(),
    DB_SSL: Joi.boolean().default(false),

    // JWT / Security
    JWT_SECRET: Joi.string().min(64).required()
        .description('Must be at least 64 characters for quantum-safe security'),
    JWT_EXPIRATION: Joi.string().default('15m'),
    JWT_REFRESH_EXPIRATION: Joi.string().default('7d'),
    JWT_PREVIOUS_SECRETS: Joi.string().optional().allow('')
        .description('Comma-separated old JWT secrets for graceful key rotation'),
    COOKIE_SECRET: Joi.string().min(32).optional(),

    // Encryption
    ENCRYPTION_KEY: Joi.string().min(32).optional()
        .description('256-bit key for data at rest encryption'),

    // OAuth / OIDC
    OAUTH_ISSUER: Joi.string().uri().optional(),
    OAUTH_CLIENT_ID: Joi.string().optional(),
    OAUTH_CLIENT_SECRET: Joi.string().optional(),
    OAUTH_REDIRECT_URI: Joi.string().uri().optional(),

    // Google OAuth
    GOOGLE_CLIENT_ID: Joi.string().optional().allow(''),
    GOOGLE_CLIENT_SECRET: Joi.string().optional().allow(''),

    // CORS
    CORS_ORIGIN: Joi.string().optional()
        .description('Comma-separated list of allowed origins'),

    // Rate Limiting
    THROTTLE_TTL: Joi.number().default(60000),
    THROTTLE_LIMIT: Joi.number().default(100),

    // Redis (for session storage)
    REDIS_HOST: Joi.string().optional(),
    REDIS_PORT: Joi.number().port().default(6379),
    REDIS_PASSWORD: Joi.string().optional().allow(''),

    // Initial Admin (for first-time setup)
    ADMIN_INITIAL_PASSWORD: Joi.string().min(12).optional(),

    // Feature Flags
    MFA_REQUIRED: Joi.boolean().default(false),
    AUDIT_LOG_ENABLED: Joi.boolean().default(true),

    // OpenTelemetry Tracing
    TRACING_ENABLED: Joi.boolean().default(false),
    OTEL_EXPORTER_OTLP_ENDPOINT: Joi.string().uri().optional()
        .description('OpenTelemetry collector endpoint (e.g., http://jaeger:4318)'),
});

