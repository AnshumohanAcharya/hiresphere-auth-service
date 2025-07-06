# 🚀 HireSphere Authentication Service

A production-ready, secure authentication service built with NestJS, featuring comprehensive security measures, Redis-based session management, and enterprise-grade OTP verification.

## 🛡️ Security Features

- **JWT Authentication** with secure refresh token rotation
- **Redis-based OTP Management** with automatic expiration
- **Progressive Rate Limiting** with intelligent blocking
- **Device Tracking** for suspicious activity detection
- **Comprehensive Audit Logging** for all operations
- **Password Strength Validation** with configurable requirements
- **Account Lockout** after multiple failed attempts
- **Helmet Security Headers** for protection against common vulnerabilities
- **CORS Protection** with configurable origins
- **Request Validation** with automatic sanitization

## 🏗️ Architecture

```
src/
├── main.ts                 # Application bootstrap with security middleware
├── app.module.ts          # Root module configuration
├── app.controller.ts      # Health checks and metrics
├── app.service.ts         # Basic application services
├── auth/                  # Authentication module
│   ├── auth.controller.ts # Auth endpoints (register, login, OTP, etc.)
│   ├── auth.service.ts    # Authentication business logic
│   ├── auth.module.ts     # Auth module configuration
│   ├── guards/            # JWT and local authentication guards
│   ├── strategies/        # Passport strategies
│   └── dto/              # Data transfer objects for validation
├── users/                 # User management module
│   ├── users.service.ts   # User CRUD operations
│   └── users.module.ts    # Users module configuration
├── security/              # Security utilities module
│   ├── security.service.ts # OTP, password validation, audit logging
│   ├── encryption.service.ts # JWT, password hashing, token generation
│   └── security.module.ts # Security module configuration
├── redis/                 # Redis service module
│   ├── redis.service.ts   # Centralized Redis operations
│   └── redis.module.ts    # Redis module configuration
├── email/                 # Email service module
│   ├── email.service.ts   # Email sending with templates
│   ├── email-templates.service.ts # HTML email templates
│   └── email.module.ts    # Email module configuration
├── database/              # Database module
│   ├── prisma.service.ts  # Prisma database client
│   └── database.module.ts # Database module configuration
└── common/                # Shared utilities
    ├── decorators/        # Custom decorators (RequestInfo, RateLimit)
    ├── guards/            # Rate limiting guards
    └── interceptors/      # Global interceptors (AuditLog)
```

## 🚀 Quick Start

### Prerequisites

- Node.js 18+ 
- PostgreSQL database
- Redis server
- SMTP email service (Gmail, SendGrid, etc.)

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd hiresphere-auth-service
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Environment Configuration**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

4. **Database Setup**
   ```bash
   # Generate Prisma client
   npx prisma generate
   
   # Run database migrations
   npx prisma migrate dev
   
   # Seed the database (optional)
   npx prisma db seed
   ```

5. **Start the application**
   ```bash
   # Development
   npm run start:dev
   
   # Production
   npm run build
   npm run start:prod
   ```

## 📋 Environment Variables

```env
# Database Configuration
DATABASE_URL="postgresql://username:password@localhost:5432/hiresphere_auth?schema=public"

# JWT Configuration
JWT_SECRET="your-super-secret-jwt-key-here-make-it-very-long-and-random"
JWT_EXPIRES_IN="15m"
JWT_REFRESH_SECRET="your-super-secret-refresh-jwt-key-here-make-it-very-long-and-random"
JWT_REFRESH_EXPIRES_IN="7d"

# Email Configuration (Gmail example)
EMAIL_HOST="smtp.gmail.com"
EMAIL_PORT=587
EMAIL_SECURE=false
EMAIL_USER="your-email@gmail.com"
EMAIL_PASS="your-app-password"
EMAIL_FROM="noreply@hiresphere.com"

# OTP Configuration
OTP_EXPIRES_IN=300000        # 5 minutes in milliseconds
OTP_LENGTH=6
OTP_MAX_ATTEMPTS=3
OTP_RESEND_COOLDOWN=60000    # 1 minute in milliseconds

# Security Configuration
BCRYPT_ROUNDS=12
MAX_FAILED_LOGIN_ATTEMPTS=5
LOGIN_LOCKOUT_DURATION=900000    # 15 minutes
LOGIN_RATE_LIMIT_WINDOW=900000   # 15 minutes

# Rate Limiting
RATE_LIMIT_WINDOW=900000         # 15 minutes in milliseconds
RATE_LIMIT_MAX_REQUESTS=100
SLOW_DOWN_WINDOW=900000          # 15 minutes in milliseconds
SLOW_DOWN_DELAY_AFTER=50
SLOW_DOWN_MAX_DELAY=20000

# Application Configuration
NODE_ENV="development"
PORT=3000
API_PREFIX="api/v1"
FRONTEND_URL="http://localhost:3000"

# Redis Configuration
REDIS_URL="redis://localhost:6379"

# Logging
LOG_LEVEL="info"
```

# Linting & Formatting
```
npm run lint     # Run ESLint
npm run lint:fix # Fix ESLint issues
npm run format   # Format code with Prettier
```

# Code Structure Best Practices

1. **Module Organization**: Each feature has its own module with clear separation of concerns
2. **Service Layer**: Business logic is contained in services, not controllers
3. **DTO Validation**: All inputs are validated using class-validator decorators
4. **Error Handling**: Comprehensive error handling with proper HTTP status codes
5. **Logging**: Structured logging with different levels (debug, info, error)
6. **Security**: Security-first approach with multiple layers of protection
7. **Documentation**: Comprehensive JSDoc comments for all public methods

# Security Considerations

1. **Password Security**: Bcrypt hashing with configurable rounds
2. **JWT Security**: Short-lived access tokens with secure refresh token rotation
3. **Rate Limiting**: Multiple layers of rate limiting (express-rate-limit + custom Redis)
4. **Input Validation**: Strict validation with whitelist approach
5. **Audit Logging**: All operations are logged for security monitoring
6. **Device Tracking**: Monitor suspicious login patterns
7. **Account Lockout**: Progressive account lockout after failed attempts

# 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

### Code Style

- Use TypeScript strict mode
- Follow NestJS conventions
- Add JSDoc comments for all public methods
- Use meaningful variable and function names
- Keep functions small and focused

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

For support and questions:
- Create an issue in the repository

---

**Built with ❤️ by the HireSphere Team**
