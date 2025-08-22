import { Injectable } from '@nestjs/common';
import * as nodemailer from 'nodemailer';

@Injectable()
export class MailerService {
  private transporter = nodemailer.createTransport({
    host: process.env.MAIL_HOST,
    port: Number(process.env.MAIL_PORT || 587),
    auth: process.env.MAIL_USER ? {
      user: process.env.MAIL_USER, pass: process.env.MAIL_PASS
    } : undefined,
  });

  async send(to: string, subject: string, html: string) {
    await this.transporter.sendMail({
      from: process.env.MAIL_FROM, to, subject, html
    });
  }
}