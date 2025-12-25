// Mock for jose library in Jest tests

export const generateKeyPair = jest.fn().mockResolvedValue({
    publicKey: { type: 'public' },
    privateKey: { type: 'private' },
});

export const SignJWT = jest.fn().mockImplementation(() => ({
    setProtectedHeader: jest.fn().mockReturnThis(),
    setIssuedAt: jest.fn().mockReturnThis(),
    setExpirationTime: jest.fn().mockReturnThis(),
    setJti: jest.fn().mockReturnThis(),
    sign: jest.fn().mockResolvedValue('mock-jwt-token'),
}));

export const jwtVerify = jest.fn().mockResolvedValue({
    payload: {
        sub: 'test-user-id',
        username: 'testuser',
        type: 'refresh',
        jti: 'test-jti',
    },
});

export const decodeProtectedHeader = jest.fn().mockReturnValue({
    alg: 'ES256',
    kid: 'test-kid',
});

export const exportJWK = jest.fn().mockResolvedValue({
    kty: 'EC',
    crv: 'P-256',
    x: 'test-x',
    y: 'test-y',
});

// Type stubs
export type JWTPayload = Record<string, unknown>;
export type JSONWebKeySet = { keys: unknown[] };
export type CryptoKey = unknown;
export type JWK = Record<string, unknown>;
