import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { UsersModule } from '../users/users.module';
import { PassportModule } from '@nestjs/passport';
import { LocalStrategy } from './local.strategy';
import { JwtStrategy } from './jwt.strategy';
import { JwtModule } from '@nestjs/jwt';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { AuthController } from './auth.controller';
import { BlockchainModule } from '../blockchain/blockchain.module';
import { MfaService } from './mfa.service';
import { KeyManagementService } from './key-management.service';

@Module({
    imports: [
        UsersModule,
        PassportModule.register({ defaultStrategy: 'jwt' }),
        BlockchainModule,
        JwtModule.registerAsync({
            imports: [ConfigModule],
            useFactory: (configService: ConfigService) => {
                const secret = configService.get<string>('JWT_SECRET');
                if (!secret) {
                    throw new Error('JWT_SECRET must be configured');
                }
                return {
                    secret,
                    signOptions: {
                        expiresIn: '1h',
                        issuer: configService.get<string>('OAUTH_ISSUER') || 'sso-system',
                    },
                };
            },
            inject: [ConfigService],
        }),
    ],
    providers: [
        AuthService,
        LocalStrategy,
        JwtStrategy,
        MfaService,
        KeyManagementService,
    ],
    controllers: [AuthController],
    exports: [AuthService, KeyManagementService],
})
export class AuthModule { }
