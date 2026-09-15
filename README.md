# Metro Backend - Runflare Deploy

## مراحل:

### 1. فایل `.env` بسازید
```
cp .env.example .env
```
و اطلاعات Melipayamak رو پر کنید.

### 2. Install dependencies
```
npm install
```

### 3. اجرا
```
node server.js
```

### 4. تست
مرورگر: `http://your-server:8000/health`

باید ببینید:
```json
{"status":"ok","message":"OTP backend is running"}
```

## API Endpoints:

| Method | Path | Description |
|--------|------|-------------|
| GET | /health | Health check |
| POST | /auth/request-otp | ارسال OTP |
| POST | /auth/resend-otp | بازارسالی OTP |
| POST | /auth/verify-otp | تایید OTP |
| GET | /auth/me | بررسی نشست |
| POST | /auth/logout | خروج |
| POST | /subscriptions/offline/activate | فعال‌سازی اشتراک |
| POST | /subscriptions/offline | همگام‌سازی اشتراک |
| GET | /config/ads | تنظیمات تبلیغات |
| POST | /admin/config/ads | تنظیم تبلیغات |
| POST | /admin/offline-activation-codes | ساخت کد فعال‌سازی |
| GET | /admin/reports/users | گزارش کاربران |
| GET | /admin/reports/offline-subscriptions | گزارش اشتراک‌ها |
| GET | /map/tiles/:z/:x/:y.png | پروکسی نقشه |
| GET | /map/foot | مسیر پیاده |
