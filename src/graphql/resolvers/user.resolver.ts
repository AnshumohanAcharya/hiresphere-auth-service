import { Resolver, Query, Args, Context, Int } from '@nestjs/graphql';
import { UseGuards } from '@nestjs/common';
import { UsersService } from '../../users/users.service';
import { JwtAuthGuard } from '../../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../../auth/guards/roles.guard';
import { Roles } from '../../auth/decorators/roles.decorator';
import { User } from '../types/user.type';
import {
  createGraphQLError,
  USER_NOT_FOUND,
} from '../../common/utils/graphql-errors';

@Resolver(() => User)
export class UserResolver {
  constructor(private readonly usersService: UsersService) {}

  @Query(() => User)
  @UseGuards(JwtAuthGuard)
  async me(@Context() context: any): Promise<User> {
    const { req } = context;
    const userId = req.user.sub;

    const user = await this.usersService.findById(userId);
    if (!user) {
      throw createGraphQLError('User not found', USER_NOT_FOUND, 404);
    }

    return {
      id: user.id,
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      isEmailVerified: user.isEmailVerified,
      isActive: user.isActive,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
    };
  }

  @Query(() => [User])
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles('admin')
  async users(
    @Args('limit', { type: () => Int, nullable: true, defaultValue: 20 })
    limit: number,
    @Args('offset', { type: () => Int, nullable: true, defaultValue: 0 })
    offset: number,
    @Args('search', { type: () => String, nullable: true }) search?: string,
  ): Promise<User[]> {
    const users = await this.usersService.findAll({ limit, offset, search });

    return users.map((user) => ({
      id: user.id,
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      isEmailVerified: user.isEmailVerified,
      isActive: user.isActive,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
    }));
  }

  @Query(() => User)
  @UseGuards(JwtAuthGuard)
  async user(@Args('id') id: string): Promise<User> {
    const user = await this.usersService.findById(id);
    if (!user) {
      throw createGraphQLError('User not found', USER_NOT_FOUND, 404);
    }

    return {
      id: user.id,
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      isEmailVerified: user.isEmailVerified,
      isActive: user.isActive,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
    };
  }
}
