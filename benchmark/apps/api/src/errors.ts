export { BadRequestException, ForbiddenException, UnauthorizedException, NotFoundException, ConflictException, ServiceUnavailableException } from '@nestjs/common';
import { HttpException } from '@nestjs/common';
export class TooManyRequestsException extends HttpException { constructor(message:string) { super(message, 429); } }
