import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import helmet from 'helmet';
import compression from 'compression';
import cookieParser from 'cookie-parser';
import { ValidationPipe, Logger } from '@nestjs/common';
import { Request, Response } from 'express';
import { ConfigService } from '@nestjs/config';

async function bootstrap() {
  const logger = new Logger('Bootstrap');

  const app = await NestFactory.create(AppModule, {
    logger: ['error', 'warn', 'log', 'debug', 'verbose'],
  });

  const configService = app.get(ConfigService);
  const isProduction = configService.get('NODE_ENV') === 'production';

  // ========================================
  // SECURITY HEADERS (ENTERPRISE GRADE)
  // ========================================
  app.use(helmet({
    // Content Security Policy
    contentSecurityPolicy: isProduction ? {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        scriptSrc: ["'self'"],
        imgSrc: ["'self'", 'data:', 'https:'],
        connectSrc: ["'self'"],
        fontSrc: ["'self'"],
        objectSrc: ["'none'"],
        mediaSrc: ["'self'"],
        frameSrc: ["'none'"],
      },
    } : false,

    // Cross-Origin settings
    crossOriginEmbedderPolicy: isProduction,
    crossOriginOpenerPolicy: isProduction ? { policy: 'same-origin' } : false,
    crossOriginResourcePolicy: isProduction ? { policy: 'same-origin' } : false,

    // Other security headers
    dnsPrefetchControl: { allow: false },
    frameguard: { action: 'deny' },
    hidePoweredBy: true,
    hsts: isProduction ? {
      maxAge: 31536000, // 1 year
      includeSubDomains: true,
      preload: true,
    } : false,
    ieNoOpen: true,
    noSniff: true,
    originAgentCluster: true,
    permittedCrossDomainPolicies: { permittedPolicies: 'none' },
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    xssFilter: true,
  }));

  // ========================================
  // PERFORMANCE
  // ========================================
  app.use(compression({
    filter: (req: Request, res: Response) => {
      if (req.headers['x-no-compression']) {
        return false;
      }
      return compression.filter(req, res);
    },
    threshold: 1024, // Only compress responses > 1KB
  }));

  // ========================================
  // COOKIES (SECURE CONFIGURATION)
  // ========================================
  app.use(cookieParser(configService.get('COOKIE_SECRET')));

  // ========================================
  // VALIDATION PIPE (ENTERPRISE STRICT)
  // ========================================
  app.useGlobalPipes(new ValidationPipe({
    whitelist: true,           // Strip non-whitelisted properties
    transform: true,           // Auto-transform payloads to DTO instances
    forbidNonWhitelisted: true, // Throw error on non-whitelisted properties
    forbidUnknownValues: true,  // Throw error on unknown values
    disableErrorMessages: isProduction, // Hide validation details in production
    validationError: {
      target: false, // Don't expose target object in errors
      value: false,  // Don't expose values in errors
    },
    transformOptions: {
      enableImplicitConversion: false, // Require explicit type decorators
    },
  }));

  // ========================================
  // CORS (ENTERPRISE CONFIGURATION)
  // ========================================
  const corsOrigin = configService.get('CORS_ORIGIN');
  const allowedOrigins = corsOrigin && corsOrigin !== '*'
    ? corsOrigin.split(',').map((o: string) => o.trim())
    : undefined;

  app.enableCors({
    origin: isProduction
      ? allowedOrigins || false  // Explicit whitelist in production
      : true,                     // Allow all in development
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: [
      'Content-Type',
      'Authorization',
      'X-Correlation-ID',
      'X-Request-ID',
      'X-CSRF-Token',
    ],
    exposedHeaders: [
      'X-Correlation-ID',
      'X-RateLimit-Limit',
      'X-RateLimit-Remaining',
      'X-RateLimit-Reset',
    ],
    maxAge: 86400, // Cache preflight for 24 hours
  });

  // ========================================
  // API PREFIX
  // ========================================
  const apiPrefix = configService.get('API_PREFIX') || '';
  if (apiPrefix) {
    app.setGlobalPrefix(apiPrefix);
  }

  // ========================================
  // GRACEFUL SHUTDOWN
  // ========================================
  app.enableShutdownHooks();

  // ========================================
  // START SERVER
  // ========================================
  const port = configService.get<number>('PORT') || 3000;
  const host = configService.get('HOST') || '0.0.0.0';

  await app.listen(port, host);

  logger.log(`
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   🚀 ENTERPRISE SSO SYSTEM STARTED                                          ║
║                                                                              ║
║   URL: ${(await app.getUrl()).padEnd(62)}     ║
║   Environment: ${(isProduction ? 'PRODUCTION' : 'DEVELOPMENT').padEnd(54)}  ║
║                                                                              ║
║   Security Features:                                                         ║
║   ✅ Helmet Security Headers                                                 ║
║   ✅ CORS Protection                                                         ║
║   ✅ Rate Limiting                                                           ║
║   ✅ Quantum-Safe Signatures (ML-DSA-65)                                     ║
║   ✅ Blockchain Audit Trail                                                  ║
║   ✅ Input Validation                                                        ║
║   ✅ MFA Support                                                             ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
    `);
}

bootstrap().catch(err => {
  console.error('Failed to start application:', err);
  process.exit(1);
});
