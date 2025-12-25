
import { Module } from '@nestjs/common';
import { OidcController } from './oidc.controller';
import { AuthModule } from '../auth/auth.module';
import { ConfigModule } from '@nestjs/config';

@Module({
    imports: [AuthModule, ConfigModule],
    controllers: [OidcController],
})
export class OauthModule { }
