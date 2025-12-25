import { Module } from '@nestjs/common';
import { BlockchainService } from './blockchain.service';
import { QuantumService } from './quantum.service';
import { KyberService } from './kyber.service';

@Module({
    providers: [BlockchainService, QuantumService, KyberService],
    exports: [BlockchainService, KyberService],
})
export class BlockchainModule { }
