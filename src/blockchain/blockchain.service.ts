import { Injectable } from '@nestjs/common';
import { QuantumService } from './quantum.service'; // Ensure this matches filename
import * as crypto from 'crypto';

class Block {
    public hash: string;
    public signature: string;
    public nonce: number = 0;

    constructor(
        public index: number,
        public timestamp: string,
        public data: string,
        public previousHash: string,
        private quantumService: QuantumService
    ) {
        this.hash = this.calculateHash();
        this.signature = this.signBlock();
    }

    calculateHash() {
        return crypto.createHash('sha256')
            .update(this.index + this.previousHash + this.timestamp + this.data + this.nonce)
            .digest('hex');
    }

    signBlock() {
        // Quantum-Safe Signature of the Hash
        return this.quantumService.sign(this.hash);
    }

    verifySignature(): boolean {
        return this.quantumService.verify(this.hash, this.signature);
    }
}

@Injectable()
export class BlockchainService {
    public chain: Block[] = [];

    constructor(private readonly quantumService: QuantumService) {
        // Postponed initialization to allow QuantumService to init
    }

    async onModuleInit() {
        await this.createGenesisBlock();
    }

    async createGenesisBlock() {
        // Wait for quantum keys if necessary (though onModuleInit usually handles order)
        this.chain.push(new Block(0, Date.now().toString(), "Genesis Block", "0", this.quantumService));
    }

    addBlock(data: any) {
        const latest = this.chain[this.chain.length - 1];
        const newBlock = new Block(
            latest.index + 1,
            Date.now().toString(),
            JSON.stringify(data),
            latest.hash,
            this.quantumService
        );
        this.chain.push(newBlock);
        return newBlock;
    }

    validateChain(): boolean {
        for (let i = 1; i < this.chain.length; i++) {
            const current = this.chain[i];
            const previous = this.chain[i - 1];

            if (current.hash !== current.calculateHash()) return false;
            if (current.previousHash !== previous.hash) return false;
            if (!current.verifySignature()) return false; // Quantum Verification
        }
        return true;
    }

    getLatestBlock() {
        return this.chain[this.chain.length - 1];
    }
}
