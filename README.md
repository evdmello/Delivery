# Courier API (NestJS + Prisma + Postgres)

### Local dev
1) Set up Postgres and Mail (smtp4dev or MailHog)
2) Create `.env` from `.env.example`
3) `npm ci`
4) `npx prisma migrate dev`
5) `npm run start:dev`

### Deploy (Railway)
- Build: `npm run build`
- Start: `npm run start:railway`
- Ensure `DATABASE_URL` and JWT/mail vars are set in Railway Variables.
