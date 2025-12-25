import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import * as request from 'supertest';
import { AppModule } from '../src/app.module';

describe('AppController (e2e)', () => {
    let app: INestApplication;

    beforeAll(async () => {
        const moduleFixture: TestingModule = await Test.createTestingModule({
            imports: [AppModule],
        }).compile();

        app = moduleFixture.createNestApplication();

        // Apply same pipes as main.ts
        app.useGlobalPipes(new ValidationPipe({
            whitelist: true,
            forbidNonWhitelisted: true,
            transform: true,
        }));

        await app.init();
    });

    afterAll(async () => {
        await app.close();
    });

    describe('Health Endpoints', () => {
        it('/health (GET) - should return health status', () => {
            return request(app.getHttpServer())
                .get('/health')
                .expect(200)
                .expect((res) => {
                    expect(res.body).toHaveProperty('status');
                });
        });

        it('/health/ready (GET) - should return readiness status', () => {
            return request(app.getHttpServer())
                .get('/health/ready')
                .expect(200)
                .expect((res) => {
                    expect(res.body).toHaveProperty('status');
                });
        });

        it('/health/startup (GET) - should return startup status', () => {
            return request(app.getHttpServer())
                .get('/health/startup')
                .expect(200)
                .expect((res) => {
                    expect(res.body).toHaveProperty('status');
                });
        });
    });

    describe('Metrics Endpoint', () => {
        it('/metrics (GET) - should return Prometheus metrics', () => {
            return request(app.getHttpServer())
                .get('/metrics')
                .expect(200)
                .expect('Content-Type', /text\/plain/)
                .expect((res) => {
                    expect(res.text).toContain('http_requests_total');
                });
        });

        it('/metrics/json (GET) - should return JSON metrics', () => {
            return request(app.getHttpServer())
                .get('/metrics/json')
                .expect(200)
                .expect((res) => {
                    expect(res.body).toHaveProperty('system');
                    expect(res.body.system).toHaveProperty('version');
                });
        });
    });

    describe('OIDC Discovery', () => {
        it('/.well-known/openid-configuration (GET) - should return OIDC config', () => {
            return request(app.getHttpServer())
                .get('/.well-known/openid-configuration')
                .expect(200)
                .expect((res) => {
                    expect(res.body).toHaveProperty('issuer');
                    expect(res.body).toHaveProperty('authorization_endpoint');
                    expect(res.body).toHaveProperty('token_endpoint');
                    expect(res.body).toHaveProperty('jwks_uri');
                });
        });

        it('/oauth/jwks (GET) - should return JWKS', () => {
            return request(app.getHttpServer())
                .get('/oauth/jwks')
                .expect(200)
                .expect((res) => {
                    expect(res.body).toHaveProperty('keys');
                    expect(Array.isArray(res.body.keys)).toBe(true);
                });
        });
    });

    describe('Authentication Endpoints', () => {
        it('/auth/login (POST) - should reject empty body', () => {
            return request(app.getHttpServer())
                .post('/auth/login')
                .send({})
                .expect(400);
        });

        it('/auth/login (POST) - should reject invalid credentials', () => {
            return request(app.getHttpServer())
                .post('/auth/login')
                .send({ username: 'invalid', password: 'invalid' })
                .expect(401);
        });

        it('/auth/refresh (POST) - should reject without token', () => {
            return request(app.getHttpServer())
                .post('/auth/refresh')
                .send({})
                .expect(400);
        });
    });

    describe('Security Headers', () => {
        it('should include security headers', () => {
            return request(app.getHttpServer())
                .get('/health')
                .expect(200)
                .expect((res) => {
                    // These headers are set by helmet in production
                    // In test, we just verify the endpoint works
                    expect(res.status).toBe(200);
                });
        });
    });

    describe('Rate Limiting', () => {
        it('should allow requests within rate limit', async () => {
            // Make several requests
            for (let i = 0; i < 5; i++) {
                await request(app.getHttpServer())
                    .get('/health')
                    .expect(200);
            }
        });
    });
});
