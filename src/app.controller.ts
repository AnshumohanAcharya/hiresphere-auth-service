import { AppService } from './app.service';
import { PrismaService } from './database/prisma.service';
import { RedisService } from './redis/redis.service';
import { Controller, Get, HttpCode, HttpStatus } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';

@ApiTags('health')
@Controller()
export class AppController {
  constructor(
    private readonly appService: AppService,
    private readonly prisma: PrismaService,
    private readonly redisService: RedisService,
  ) {}

  @Get()
  @ApiOperation({ summary: 'Root endpoint' })
  @ApiResponse({
    status: 200,
    description: 'Application is running',
  })
  getHello(): { message: string; timestamp: string; version: string } {
    return {
      message: this.appService.getHello(),
      timestamp: new Date().toISOString(),
      version: '1.0.0',
    };
  }

  @Get('health')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Health check endpoint' })
  @ApiResponse({
    status: 200,
    description: 'Service is healthy',
  })
  @ApiResponse({
    status: 503,
    description: 'Service is unhealthy',
  })
  async getHealth(): Promise<{
    status: string;
    timestamp: string;
    uptime: number;
    database: { status: string; responseTime?: number };
    redis: { status: string; responseTime?: number };
    memory: { used: number; total: number; percentage: number };
  }> {
    const startTime = Date.now();
    let dbStatus = 'unhealthy';
    let dbResponseTime: number | undefined;

    try {
      // Test database connection
      await this.prisma.$queryRaw`SELECT 1`;
      dbStatus = 'healthy';
      dbResponseTime = Date.now() - startTime;
    } catch {
      dbStatus = 'unhealthy';
    }

    // Test Redis connection
    const redisStartTime = Date.now();
    const redisStatus = (await this.redisService.ping())
      ? 'healthy'
      : 'unhealthy';
    const redisResponseTime =
      redisStatus === 'healthy' ? Date.now() - redisStartTime : undefined;

    // Get memory usage
    const memUsage = process.memoryUsage();
    const totalMemory = memUsage.heapTotal;
    const usedMemory = memUsage.heapUsed;
    const memoryPercentage = (usedMemory / totalMemory) * 100;

    const overallStatus =
      dbStatus === 'healthy' && redisStatus === 'healthy'
        ? 'healthy'
        : 'unhealthy';

    return {
      status: overallStatus,
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      database: {
        status: dbStatus,
        responseTime: dbResponseTime,
      },
      redis: {
        status: redisStatus,
        responseTime: redisResponseTime,
      },
      memory: {
        used: Math.round(usedMemory / 1024 / 1024), // MB
        total: Math.round(totalMemory / 1024 / 1024), // MB
        percentage: Math.round(memoryPercentage * 100) / 100,
      },
    };
  }

  @Get('metrics')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Application metrics endpoint' })
  @ApiResponse({
    status: 200,
    description: 'Application metrics',
  })
  async getMetrics(): Promise<{
    timestamp: string;
    uptime: number;
    memory: {
      heapUsed: number;
      heapTotal: number;
      external: number;
      rss: number;
    };
    cpu: {
      usage: number;
    };
    process: {
      pid: number;
      version: string;
      platform: string;
      arch: string;
    };
    database: {
      connectionPool: {
        active: number;
        idle: number;
        total: number;
      };
    };
    redis: {
      status: string;
    };
  }> {
    const memUsage = process.memoryUsage();
    const cpuUsage = process.cpuUsage();
    const redisStatus = (await this.redisService.ping())
      ? 'connected'
      : 'disconnected';

    return {
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      memory: {
        heapUsed: Math.round(memUsage.heapUsed / 1024 / 1024), // MB
        heapTotal: Math.round(memUsage.heapTotal / 1024 / 1024), // MB
        external: Math.round(memUsage.external / 1024 / 1024), // MB
        rss: Math.round(memUsage.rss / 1024 / 1024), // MB
      },
      cpu: {
        usage: Math.round((cpuUsage.user + cpuUsage.system) / 1000), // ms
      },
      process: {
        pid: process.pid,
        version: process.version,
        platform: process.platform,
        arch: process.arch,
      },
      database: {
        connectionPool: {
          active: 0, // Prisma doesn't expose connection pool metrics directly
          idle: 0,
          total: 0,
        },
      },
      redis: {
        status: redisStatus,
      },
    };
  }
}
