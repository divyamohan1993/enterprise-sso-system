import { Module } from '@nestjs/common';
import { QuantumSecurityService } from './quantum.service';

@Module({
    providers: [QuantumSecurityService],
    exports: [QuantumSecurityService],
})
export class CryptoModule { }
