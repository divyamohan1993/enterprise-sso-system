// Jest setup file for mocking external modules and exports mock

// Mock ml_dsa65 for quantum signature
export const ml_dsa65 = {
    keygen: () => ({
        publicKey: new Uint8Array(32).fill(1),
        secretKey: new Uint8Array(64).fill(2),
    }),
    sign: jest.fn().mockReturnValue(new Uint8Array(128).fill(3)),
    verify: jest.fn().mockReturnValue(true),
};
