import { BadRequestException, Injectable, UnauthorizedException } from '@nestjs/common';
import { UsersService } from '../users/users.service';
import * as bcrypt from 'bcryptjs';
import { PrismaService } from '../prisma.service';
import { JwtService } from '@nestjs/jwt';
import * as crypto from 'crypto';
import { MailerService } from '../mailer/mailer.service';

const SALT_ROUNDS = 12;
const MAX_FAILED = 5;

@Injectable()
export class AuthService {
  constructor(
    private users: UsersService,
    private prisma: PrismaService,
    private jwt: JwtService,
    private mailer: MailerService,
  ) {}

  async register(email: string, password: string, phone?: string) {
    const exists = await this.users.findByEmail(email);
    if (exists) throw new BadRequestException('Email already registered');
    const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
    const user = await this.users.create({ email, passwordHash, phone });
    return this.issueTokens(user.id, email);
  }

  async login(email: string, password: string) {
    const user = await this.users.findByEmail(email);
    if (!user) throw new UnauthorizedException('Invalid credentials');

    if (user.lockedUntil && user.lockedUntil > new Date()) {
      throw new UnauthorizedException('Account temporarily locked');
    }
    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) {
      const failed = user.failedLoginCount + 1;
      const lockedUntil = failed >= MAX_FAILED ? new Date(Date.now() + 15 * 60_000) : null;
      await this.users.update(user.id, { failedLoginCount: failed, lockedUntil });
      throw new UnauthorizedException('Invalid credentials');
    }
    await this.users.update(user.id, { failedLoginCount: 0, lockedUntil: null });
    return this.issueTokens(user.id, user.email);
  }

  async refresh(userId: string, refreshToken: string) {
    const user = await this.users.findById(userId);
    if (!user || !user.refreshTokenHash) throw new UnauthorizedException('No session');
    const match = await bcrypt.compare(refreshToken, user.refreshTokenHash);
    if (!match) throw new UnauthorizedException('Invalid session');
    return this.issueTokens(user.id, user.email); // rotate
  }

  private async issueTokens(userId: string, email: string) {
    const access = await this.jwt.signAsync(
      { sub: userId, email },
      { secret: process.env.JWT_ACCESS_SECRET!, expiresIn: process.env.JWT_ACCESS_TTL || '15m' }
    );
    const refreshPlain = crypto.randomBytes(48).toString('hex');
    const refreshHash = await bcrypt.hash(refreshPlain, SALT_ROUNDS);
    await this.users.update(userId, { refreshTokenHash: refreshHash });
    return { accessToken: access, refreshToken: refreshPlain };
  }

  async forgot(email: string) {
    const user = await this.users.findByEmail(email);
    // Don't reveal account existence
    if (!user) return { ok: true };

    const tokenPlain = crypto.randomBytes(32).toString('hex');
    const tokenHash = crypto.createHash('sha256').update(tokenPlain).digest('hex');
    const expires = new Date(Date.now() + 15 * 60_000);

    await this.users.update(user.id, {
      resetTokenHash: tokenHash,
      resetTokenExpires: expires,
    });

    const resetUrl = `${process.env.CLIENT_RESET_URL}?token=${tokenPlain}&email=${encodeURIComponent(email)}`;
    await this.mailer.send(
      email,
      'Reset your password',
      `<p>We received a request to reset your password.</p>
       <p><a href="${resetUrl}">Click here to reset</a> (valid for 15 minutes).</p>
       <p>If you didn't request this, you can ignore this email.</p>`
    );

    return { ok: true };
  }

  async reset(token: string, password: string) {
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const user = await this.prisma.user.findFirst({
      where: { resetTokenHash: tokenHash, resetTokenExpires: { gt: new Date() } },
    });
    if (!user) throw new BadRequestException('Invalid or expired token');

    const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
    await this.users.update(user.id, {
      passwordHash,
      resetTokenHash: null,
      resetTokenExpires: null,
      failedLoginCount: 0,
      lockedUntil: null,
    });
    return { ok: true };
  }

  async me(userId: string) {
    const u = await this.users.findById(userId);
    return { id: u.id, email: u.email, phone: u.phone, createdAt: u.createdAt };
  }

  async logout(userId: string) {
    await this.users.update(userId, { refreshTokenHash: null });
    return { ok: true };
  }
}