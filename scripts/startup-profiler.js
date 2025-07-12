#!/usr/bin/env node

/**
 * Startup Profiler for HireSphere Auth Service
 *
 * This script helps identify startup bottlenecks by measuring
 * different phases of the application startup process.
 */

const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

class StartupProfiler {
  constructor() {
    this.startTime = Date.now();
    this.phases = [];
  }

  startPhase(name) {
    const phase = {
      name,
      startTime: Date.now(),
      endTime: null,
      duration: null,
    };
    this.phases.push(phase);
    console.log(`🔄 Starting phase: ${name}`);
    return phase;
  }

  endPhase(name) {
    const phase = this.phases.find((p) => p.name === name && !p.endTime);
    if (phase) {
      phase.endTime = Date.now();
      phase.duration = phase.endTime - phase.startTime;
      console.log(`✅ Completed phase: ${name} (${phase.duration}ms)`);
    }
  }

  async checkDatabase() {
    const phase = this.startPhase('Database Connection');
    try {
      // Check if PostgreSQL is running
      const { exec } = require('child_process');
      const util = require('util');
      const execAsync = util.promisify(exec);

      await execAsync('pg_isready -h localhost -p 5432');
      this.endPhase('Database Connection');
      return true;
    } catch (error) {
      console.log('⚠️  Database not ready or not running');
      this.endPhase('Database Connection');
      return false;
    }
  }

  async checkRedis() {
    const phase = this.startPhase('Redis Connection');
    try {
      const { exec } = require('child_process');
      const util = require('util');
      const execAsync = util.promisify(exec);

      await execAsync('redis-cli ping');
      this.endPhase('Redis Connection');
      return true;
    } catch (error) {
      console.log('⚠️  Redis not ready or not running');
      this.endPhase('Redis Connection');
      return false;
    }
  }

  async checkDependencies() {
    const phase = this.startPhase('Dependencies Check');

    // Check if node_modules exists
    const nodeModulesPath = path.join(process.cwd(), 'node_modules');
    if (!fs.existsSync(nodeModulesPath)) {
      console.log('❌ node_modules not found. Run: pnpm install');
      this.endPhase('Dependencies Check');
      return false;
    }

    // Check if Prisma client is generated
    const prismaClientPath = path.join(nodeModulesPath, '@prisma', 'client');
    if (!fs.existsSync(prismaClientPath)) {
      console.log('⚠️  Prisma client not generated. Run: pnpm db:generate');
    }

    this.endPhase('Dependencies Check');
    return true;
  }

  async startApplication() {
    const phase = this.startPhase('Application Startup');

    return new Promise((resolve, reject) => {
      const child = spawn('pnpm', ['start:dev'], {
        stdio: 'pipe',
        shell: true,
      });

      let output = '';
      let startupComplete = false;

      child.stdout.on('data', (data) => {
        const message = data.toString();
        output += message;

        // Check for startup completion indicators
        if (
          message.includes('Application is running on:') &&
          !startupComplete
        ) {
          startupComplete = true;
          this.endPhase('Application Startup');

          // Extract startup time from output
          const startupTimeMatch = message.match(/Total startup time: (\d+)ms/);
          if (startupTimeMatch) {
            console.log(`⏱️  Total startup time: ${startupTimeMatch[1]}ms`);
          }

          child.kill('SIGTERM');
          resolve(output);
        }
      });

      child.stderr.on('data', (data) => {
        console.error(`stderr: ${data}`);
      });

      child.on('close', (code) => {
        if (!startupComplete) {
          this.endPhase('Application Startup');
          reject(new Error(`Application exited with code ${code}`));
        }
      });

      // Timeout after 30 seconds
      setTimeout(() => {
        if (!startupComplete) {
          child.kill('SIGTERM');
          this.endPhase('Application Startup');
          reject(new Error('Application startup timeout after 30 seconds'));
        }
      }, 30000);
    });
  }

  generateReport() {
    const totalTime = Date.now() - this.startTime;
    console.log('\n📊 Startup Performance Report');
    console.log('============================');

    this.phases.forEach((phase) => {
      if (phase.duration !== null) {
        const percentage = ((phase.duration / totalTime) * 100).toFixed(1);
        console.log(`${phase.name}: ${phase.duration}ms (${percentage}%)`);
      }
    });

    console.log(`\nTotal time: ${totalTime}ms`);

    // Identify bottlenecks
    const slowPhases = this.phases.filter((p) => p.duration > 2000);
    if (slowPhases.length > 0) {
      console.log('\n🐌 Potential bottlenecks:');
      slowPhases.forEach((phase) => {
        console.log(`- ${phase.name}: ${phase.duration}ms`);
      });
    }
  }
}

async function main() {
  console.log('🔍 HireSphere Auth Service Startup Profiler');
  console.log('===========================================\n');

  const profiler = new StartupProfiler();

  try {
    // Check dependencies
    await profiler.checkDependencies();

    // Check external services
    await profiler.checkDatabase();
    await profiler.checkRedis();

    // Start application and measure startup time
    await profiler.startApplication();

    // Generate report
    profiler.generateReport();
  } catch (error) {
    console.error('❌ Profiling failed:', error.message);
    profiler.generateReport();
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}

module.exports = StartupProfiler;
