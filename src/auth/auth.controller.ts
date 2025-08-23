import { Body, Controller, Get, Headers, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { z } from 'zod';
import { RegisterDto, LoginDto, ForgotDto, ResetDto } from './dto';
import { JwtService } from '@nestjs/jwt';

@Controller('auth')
export class AuthController {
  constructor(private auth: AuthService, private jwt: JwtService) {}

  @Post('register')
  async register(@Body() body: unknown) {
    const dto = RegisterDto.parse(body);
    return this.auth.register(dto.firstName, dto.lastName, dto.email.toLowerCase(), dto.password, dto.phone);
  }

  @Post('login')
  async login(@Body() body: unknown) {
    const dto = LoginDto.parse(body);
    return this.auth.login(dto.email.toLowerCase(), dto.password);
  }

  @Post('refresh')
  async refresh(@Body() body: any) {
    // body: { userId, refreshToken }
    const shape = z.object({ userId: z.string().min(1), refreshToken: z.string().min(20) });
    const dto = shape.parse(body);
    return this.auth.refresh(dto.userId, dto.refreshToken);
  }

  @Post('forgot')
  async forgot(@Body() body: unknown) {
    const dto = ForgotDto.parse(body);
    return this.auth.forgot(dto.email.toLowerCase());
  }

  @Post('reset')
  async reset(@Body() body: unknown) {
    const dto = ResetDto.parse(body);
    return this.auth.reset(dto.token, dto.password);
  }

  @Get('me')
  async me(@Headers('authorization') authz?: string) {
    if (!authz?.startsWith('Bearer ')) return { error: 'No token' };
    const token = authz.slice(7);
    const payload = await this.jwt.verifyAsync(token, { secret: process.env.JWT_ACCESS_SECRET! });
    return this.auth.me(payload.sub);
  }

  @Post('logout')
  async logout(@Body() body: any) {
    const shape = z.object({ userId: z.string().min(1) });
    const dto = shape.parse(body);
    return this.auth.logout(dto.userId);
  }
}