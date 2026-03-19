# Alino v5 — Setup Guide

## Required Railway Environment Variables

| Variable | Required | Description |
|---|---|---|
| `MONGODB_URI` | ✅ Yes | MongoDB Atlas connection string |
| `JWT_SECRET` | ✅ Yes | Any long random string (e.g. 64 chars) |
| `PORT` | Auto | Set by Railway automatically |

## Optional Variables (features work without them, just degraded)

| Variable | Description | If missing |
|---|---|---|
| `CLOUDINARY_CLOUD_NAME` | Cloudinary dashboard | Images stored in MongoDB |
| `CLOUDINARY_API_KEY` | Cloudinary dashboard | Images stored in MongoDB |
| `CLOUDINARY_API_SECRET` | Cloudinary dashboard | Images stored in MongoDB |
| `EMAIL_USER` | Your Gmail address | Email features disabled, users auto-verified |
| `EMAIL_PASS` | Gmail App Password | Email features disabled |
| `APP_URL` | Your Railway URL e.g. https://alino.up.railway.app | Email links won't work |
| `ADMIN_EMAIL` | Email that gets admin role on signup | Use Railway console to manually set admin |
| `NODE_ENV` | Set to `production` | Runs in dev mode |

## Getting Gmail App Password
1. Go to myaccount.google.com
2. Security → 2-Step Verification (must be ON)
3. Search "App passwords"
4. Create one called "Alino"
5. Copy the 16-character password → that is your EMAIL_PASS

## Seeding Demo Data
After first deploy, open Railway terminal and run:
```
node seed.mjs
```
This creates:
- 1 admin account (credentials shown in terminal output)
- 10 demo users (all with password: Demo@1234)
- 10 real-looking posts with descriptions, tags, scores
- Seed comments and likes between users

## New in v5
- **Profile fields**: Full Name, Age, College, State (NE India) collected at signup
- **Age gate**: Users must be 16+ to register
- **Account lockout**: 5 failed logins locks account for 30 minutes
- **Login history**: Admin can view every login attempt per user with IP + device
- **IP tracking**: Registration IP stored per user, visible in admin panel
- **Username suggestions**: If username taken, 3 alternatives shown instantly
- **Duplicate post titles**: Blocked — every post title must be unique
- **Post rate limit**: Max 1 post per hour per user
- **Profanity filter**: Blocks inappropriate language in posts and comments
- **Bulk delete**: Admin can delete all flagged posts in one click
- **Password strength**: Meter on signup + backend enforcement (must have letter + number/symbol)

## APK Generation
1. Deploy to Railway first
2. Go to pwabuilder.com
3. Enter your Railway URL
4. Download → Android → APK

## Free Tier Summary
- Railway: $5 free credit/month (app costs ~$1-2/month)
- MongoDB Atlas: 512MB free forever
- Cloudinary: 25GB free forever
- Gmail SMTP: 500 emails/day free forever
