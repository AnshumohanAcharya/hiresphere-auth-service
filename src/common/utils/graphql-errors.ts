export class GraphQLError extends Error {
  constructor(
    message: string,
    public code: string,
    public statusCode: number = 400,
  ) {
    super(message);
    this.name = 'GraphQLError';
  }
}

export const createGraphQLError = (
  message: string,
  code: string,
  statusCode?: number,
) => {
  return new GraphQLError(message, code, statusCode);
};

export const USER_NOT_FOUND = 'USER_NOT_FOUND';
export const INVALID_CREDENTIALS = 'INVALID_CREDENTIALS';
export const EMAIL_NOT_VERIFIED = 'EMAIL_NOT_VERIFIED';
export const OTP_INVALID = 'OTP_INVALID';
export const OTP_EXPIRED = 'OTP_EXPIRED';
export const TOO_MANY_ATTEMPTS = 'TOO_MANY_ATTEMPTS';
export const UNAUTHORIZED = 'UNAUTHORIZED';
export const FORBIDDEN = 'FORBIDDEN';
