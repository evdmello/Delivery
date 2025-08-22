import { z } from 'zod';

export const RegisterDto = z.object({
  email: z.string().email(),
  password: z.string().min(8),
  phone: z.string().optional(),
});
export type RegisterDto = z.infer<typeof RegisterDto>;

export const LoginDto = z.object({
  email: z.string().email(),
  password: z.string().min(8),
});
export type LoginDto = z.infer<typeof LoginDto>;

export const ForgotDto = z.object({ email: z.string().email() });
export type ForgotDto = z.infer<typeof ForgotDto>;

export const ResetDto = z.object({
  token: z.string().min(32),
  password: z.string().min(8),
});
export type ResetDto = z.infer<typeof ResetDto>;