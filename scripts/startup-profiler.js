#!/usr/bin/env node

/**
 * Startup Profiler for HireSphere Auth Service (Refactored)
 *
 * Uses Node's built-in timers and a generic service checker to reduce boilerplate.
 */

const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const { promisify } = require('util');
const execAsync = promisify(require('child_process').exec);

async function checkService(name, cmd) {
  console.time(name);
  try {
    await execAsync(cmd);
  } catch {
    console.warn(`⚠️  ${name} failed`);
  }
  console.timeEnd(name);
}

async function checkDependencies() {
  console.time('Dependencies Check');
  const nodeModulesPath = path.join(process.cwd(), 'node_modules');
  if (!fs.existsSync(nodeModulesPath)) {
    console.warn('❌ node_modules not found. Run: pnpm install');
    console.timeEnd('Dependencies Check');
    return false;
  }
  // Check if Prisma client is generated
  const prismaClientPath = path.join(nodeModulesPath, '@prisma', 'client');
  if (!fs.existsSync(prismaClientPath)) {
    console.warn('⚠️  Prisma client not generated. Run: pnpm db:generate');
  }
  console.timeEnd('Dependencies Check');
  return true;
}

async function startApplication() {
  console.time('Application Startup');
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
      if (message.includes('Application is running on:') && !startupComplete) {
        startupComplete = true;
        console.timeEnd('Application Startup');
        child.kill('SIGTERM');
        resolve(output);
      }
    });

    child.stderr.on('data', (data) => {
      console.error(`stderr: ${data}`);
    });

    child.on('close', (code) => {
      if (!startupComplete) {
        console.timeEnd('Application Startup');
        reject(new Error(`Application exited with code ${code}`));
      }
    });

    setTimeout(() => {
      if (!startupComplete) {
        child.kill('SIGTERM');
        console.timeEnd('Application Startup');
        reject(new Error('Application startup timeout after 30 seconds'));
      }
    }, 30000);
  });
}

async function main() {
  console.log('🔍 HireSphere Auth Service Startup Profiler (Refactored)');
  console.log('===========================================\n');
  const startTime = Date.now();

  try {
    await checkDependencies();
    await checkService(
      'Database Connection',
      'pg_isready -h localhost -p 5432',
    );
    await checkService('Redis Connection', 'redis-cli ping');
    await startApplication();
  } catch (error) {
    console.error('❌ Profiling failed:', error.message);
  }

  const totalTime = Date.now() - startTime;
  console.log(`\nTotal time: ${totalTime}ms`);
}

if (require.main === module) {
  main();
}
