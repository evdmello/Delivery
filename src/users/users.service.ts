import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma.service';

@Injectable()
export class UsersService {
  constructor(private prisma: PrismaService) {}

  findByEmail(email: string) {
    return this.prisma.user.findUnique({ where: { email } });
  }
  findById(id: string) {
    return this.prisma.user.findUnique({ where: { id } });
  }
  create(data: { email: string; passwordHash: string; phone?: string }) {
    return this.prisma.user.create({ data });
  }
  update(id: string, data: any) {
    return this.prisma.user.update({ where: { id }, data });
  }
}