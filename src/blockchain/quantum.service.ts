
import { Injectable, OnModuleInit } from '@nestjs/common';
// @ts-ignore
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa';
import * as crypto from 'node:crypto';

@Injectable()
export class QuantumService implements OnModuleInit {
    private publicKey: Uint8Array;
    private privateKey: Uint8Array;

    async onModuleInit() {
        // Shim global crypto for @noble generic usage in Node
        if (!globalThis.crypto) {
            // @ts-ignore
            globalThis.crypto = crypto.webcrypto;
        }

        // Generate Quantum-Safe Keys (Dilithium-65)
        // Using default entropy source (shimmed webcrypto)
        const keys = ml_dsa65.keygen();
        this.publicKey = keys.publicKey;
        this.privateKey = keys.secretKey;
        console.log('[QuantumService] Post-Quantum Keys Generated (ML-DSA-65/Dilithium)');
    }

    sign(message: string): string {
        const msgBytes = new TextEncoder().encode(message);
        // Sign without passing generic random function as option
        const signature = ml_dsa65.sign(this.privateKey, msgBytes);
        return Buffer.from(signature).toString('hex');
    }

    verify(message: string, signatureHex: string, publicKeyHex?: string): boolean {
        const msgBytes = new TextEncoder().encode(message);
        const signature = Uint8Array.from(Buffer.from(signatureHex, 'hex'));
        const pubKey = publicKeyHex
            ? Uint8Array.from(Buffer.from(publicKeyHex, 'hex'))
            : this.publicKey;

        return ml_dsa65.verify(pubKey, msgBytes, signature);
    }

    getPublicKey(): string {
        return Buffer.from(this.publicKey).toString('hex');
    }
}
