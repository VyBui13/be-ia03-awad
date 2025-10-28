import { Controller, Post, Body, HttpCode, HttpStatus } from '@nestjs/common';
import { UserService } from './user.service';
import { RegisterUserDto } from './dto/register-user.dto';
import { LoginUserDto } from './dto/login-user.dto';

@Controller('user') // Định nghĩa route prefix là /user
export class UserController {
  constructor(private readonly userService: UserService) {}

  @Post('register') // Endpoint là POST /user/register
  @HttpCode(HttpStatus.CREATED) // Trả về status 201 Created
  async register(@Body() registerUserDto: RegisterUserDto) {
    await this.userService.register(registerUserDto);
  }

  @Post('login')
  @HttpCode(HttpStatus.OK) // Trả về 200 OK
  async login(@Body() loginUserDto: LoginUserDto) {
    // Không cần try/catch vì Exception Filter của NestJS sẽ tự bắt lỗi
    return this.userService.login(loginUserDto);
  }
}
