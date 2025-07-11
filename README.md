# HireSphere Auth Service

A secure, scalable authentication service built with NestJS, GraphQL, and PostgreSQL.

## Features

- 🔐 **GraphQL API** - Modern GraphQL interface for all authentication operations
- 🛡️ **Security First** - JWT tokens, rate limiting, OTP verification, and audit logging
- 📧 **Email Integration** - Automated email verification and password reset
- 🗄️ **PostgreSQL** - Robust database with Prisma ORM
- ⚡ **Redis Caching** - Fast session management and OTP storage
- 📊 **Health Monitoring** - Comprehensive health checks and metrics
- 🔍 **Audit Logging** - Complete request tracking and security events

## Quick Start

### Prerequisites

- Node.js 18+ 
- PostgreSQL 12+
- Redis 6+
- pnpm (recommended) or npm

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd hiresphere-auth-service
   ```

2. **Install dependencies**
   ```bash
   pnpm install
   ```

3. **Environment Setup**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

4. **Database Setup**
   ```bash
   pnpm db:generate
   pnpm db:migrate
   pnpm db:seed
   ```

5. **Start the service**
   ```bash
   pnpm start:dev
   ```

The service will be available at:
- **GraphQL Playground**: http://localhost:4000/graphql
- **Health Check**: http://localhost:4000/health
- **API Documentation**: http://localhost:4000/docs

## GraphQL API

### Authentication Mutations

#### Register User
```graphql
mutation Register($input: RegisterInput!) {
  register(input: $input) {
    message
    userId
    emailSent
  }
}
```

#### Login
```graphql
mutation Login($input: LoginInput!) {
  login(input: $input) {
    accessToken
    refreshToken
    user {
      id
      email
      firstName
      lastName
      isEmailVerified
      isActive
      createdAt
      updatedAt
    }
    message
  }
}
```

#### Verify OTP
```graphql
mutation VerifyOtp($input: VerifyOtpInput!) {
  verifyOtp(input: $input) {
    message
    isVerified
  }
}
```

#### Forgot Password
```graphql
mutation ForgotPassword($input: ForgotPasswordInput!) {
  forgotPassword(input: $input) {
    message
    emailSent
  }
}
```

#### Reset Password
```graphql
mutation ResetPassword($input: ResetPasswordInput!) {
  resetPassword(input: $input) {
    message
    success
  }
}
```

#### Refresh Token
```graphql
mutation RefreshToken($input: RefreshTokenInput!) {
  refreshToken(input: $input) {
    accessToken
    refreshToken
    message
  }
}
```

#### Logout
```graphql
mutation Logout {
  logout
}
```

### User Queries

#### Get Current User
```graphql
query Me {
  me {
    id
    email
    firstName
    lastName
    isEmailVerified
    isActive
    createdAt
    updatedAt
  }
}
```

#### Get All Users (Admin)
```graphql
query Users {
  users {
    id
    email
    firstName
    lastName
    isEmailVerified
    isActive
    createdAt
    updatedAt
  }
}
```

#### Get User by ID
```graphql
query User($id: String!) {
  user(id: $id) {
    id
    email
    firstName
    lastName
    isEmailVerified
    isActive
    createdAt
    updatedAt
  }
}
```

## Input Types

### RegisterInput
```graphql
input RegisterInput {
  email: String!
  firstName: String!
  lastName: String!
  password: String!
}
```

### LoginInput
```graphql
input LoginInput {
  email: String!
  password: String!
}
```

### VerifyOtpInput
```graphql
input VerifyOtpInput {
  email: String!
  otp: String!
  type: String!
}
```

## Authentication

### JWT Tokens
- **Access Token**: Short-lived (15 minutes) for API access
- **Refresh Token**: Long-lived (7 days) for token renewal

### Headers
Include the access token in GraphQL requests:
```
Authorization: Bearer <access_token>
```

## Security Features

- **Rate Limiting**: Prevents abuse with configurable limits
- **OTP Verification**: Email-based verification for registration and password reset
- **Password Strength**: Enforces strong password requirements
- **Audit Logging**: Tracks all authentication events
- **Session Management**: Redis-based session storage with device tracking
- **Security Headers**: Helmet.js for protection against common vulnerabilities

## Environment Variables

```env
# Server
PORT=4000
NODE_ENV=development

# Database
DATABASE_URL="postgresql://user:password@localhost:5432/hiresphere_auth"

# Redis
REDIS_URL="redis://localhost:6379"

# JWT
JWT_SECRET=your-jwt-secret
JWT_REFRESH_SECRET=your-refresh-secret
JWT_EXPIRES_IN=15m
JWT_REFRESH_EXPIRES_IN=7d

# Email
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-app-password

# Rate Limiting
RATE_LIMIT_WINDOW=900000
RATE_LIMIT_MAX_REQUESTS=100
SLOW_DOWN_WINDOW=900000
SLOW_DOWN_DELAY_AFTER=50
SLOW_DOWN_MAX_DELAY=20000
```

## Development

### Available Scripts

```bash
# Development
pnpm start:dev          # Start in development mode
pnpm start:debug        # Start with debugger

# Production
pnpm build              # Build the application
pnpm start:prod         # Start in production mode

# Database
pnpm db:generate        # Generate Prisma client
pnpm db:migrate         # Run database migrations
pnpm db:studio          # Open Prisma Studio
pnpm db:seed            # Seed the database

# Code Quality
pnpm lint               # Run ESLint
pnpm format             # Format code with Prettier
pnpm format:check       # Check code formatting
```

### Project Structure

```
src/
├── auth/                 # Authentication logic
│   ├── dto/             # Data transfer objects
│   ├── guards/          # JWT and local auth guards
│   └── strategies/      # Passport strategies
├── common/              # Shared utilities
│   ├── decorators/      # Custom decorators
│   ├── guards/          # Rate limiting guards
│   └── interceptors/    # Audit logging
├── database/            # Database configuration
├── email/               # Email service
├── graphql/             # GraphQL implementation
│   ├── inputs/          # GraphQL input types
│   ├── resolvers/       # GraphQL resolvers
│   └── types/           # GraphQL object types
├── redis/               # Redis service
├── security/            # Security utilities
└── users/               # User management
```

## API Endpoints

### REST Endpoints (Legacy)
- `GET /health` - Health check
- `GET /metrics` - Application metrics
- `GET /docs` - API documentation (Swagger)

### GraphQL Endpoint
- `POST /graphql` - GraphQL API
- `GET /graphql` - GraphQL Playground (development)

## Monitoring

### Health Check
```bash
curl http://localhost:4000/health
```

### Metrics
```bash
curl http://localhost:4000/metrics
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License.
