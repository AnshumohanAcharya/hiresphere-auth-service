import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { GqlExecutionContext } from '@nestjs/graphql';
import { ROLES_KEY } from '../decorators/roles.decorator';

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndOverride<string[]>(
      ROLES_KEY,
      [context.getHandler(), context.getClass()],
    );

    if (!requiredRoles) {
      return true;
    }

    const gqlCtx = GqlExecutionContext.create(context);
    const { req } = gqlCtx.getContext();
    const user = req.user;

    if (!user) {
      return false;
    }

    // For now, we'll implement a simple admin check
    // In a real application, you'd have a roles field in the user model
    // and check against that
    return (
      requiredRoles.includes('admin') && user.email === 'admin@hiresphere.com'
    );
  }
}
