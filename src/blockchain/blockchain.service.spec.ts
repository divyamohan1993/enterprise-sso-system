import { Test, TestingModule } from '@nestjs/testing';
import { BlockchainService } from './blockchain.service';
import { QuantumService } from './quantum.service';

describe('BlockchainService', () => {
    let service: BlockchainService;

    beforeEach(async () => {
        // Create a mock quantum service
        const mockQuantumService = {
            sign: jest.fn().mockReturnValue('mock-signature-hex-string'),
            verify: jest.fn().mockReturnValue(true),
            getPublicKey: jest.fn().mockReturnValue('mock-public-key'),
            onModuleInit: jest.fn(),
        };

        const module: TestingModule = await Test.createTestingModule({
            providers: [
                BlockchainService,
                { provide: QuantumService, useValue: mockQuantumService },
            ],
        }).compile();

        service = module.get<BlockchainService>(BlockchainService);

        // Initialize blockchain (creates genesis block)
        await service.onModuleInit();
    });

    it('should be defined', () => {
        expect(service).toBeDefined();
    });

    describe('genesis block', () => {
        it('should have genesis block after initialization', () => {
            expect(service.chain.length).toBeGreaterThanOrEqual(1);
            expect(service.chain[0].index).toBe(0);
        });

        it('should have a valid hash on genesis block', () => {
            const genesis = service.chain[0];
            expect(genesis.hash).toBeDefined();
            expect(genesis.hash.length).toBe(64); // SHA-256 hex
        });
    });

    describe('addBlock', () => {
        it('should add a new block to the chain', () => {
            const initialLength = service.chain.length;

            service.addBlock({
                event: 'TEST_EVENT',
                data: 'test data',
            });

            expect(service.chain.length).toBe(initialLength + 1);
        });

        it('should link new block to previous block', () => {
            const previousBlock = service.getLatestBlock();

            const newBlock = service.addBlock({
                event: 'LINKED_EVENT',
            });

            expect(newBlock.previousHash).toBe(previousBlock.hash);
        });

        it('should have signature', () => {
            const block = service.addBlock({
                event: 'SIGNED_EVENT',
            });

            expect(block.signature).toBeDefined();
            expect(typeof block.signature).toBe('string');
            expect(block.signature.length).toBeGreaterThan(0);
        });
    });

    describe('validateChain', () => {
        it('should validate an untampered chain', () => {
            service.addBlock({ event: 'EVENT_1' });
            service.addBlock({ event: 'EVENT_2' });
            service.addBlock({ event: 'EVENT_3' });

            const isValid = service.validateChain();

            expect(isValid).toBe(true);
        });
    });

    describe('getLatestBlock', () => {
        it('should return the most recent block', () => {
            service.addBlock({ event: 'EVENT_1' });
            const lastBlock = service.addBlock({ event: 'LAST_EVENT' });

            const latest = service.getLatestBlock();

            expect(latest.index).toBe(lastBlock.index);
            expect(latest.hash).toBe(lastBlock.hash);
        });
    });
});
