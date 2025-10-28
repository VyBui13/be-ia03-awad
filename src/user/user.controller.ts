import { Controller, Post, Body, HttpCode, HttpStatus } from '@nestjs/common';
import { UserService } from './user.service';
import { RegisterUserDto } from './dto/register-user.dto';

@Controller('user') // Định nghĩa route prefix là /user
export class UserController {
  constructor(private readonly userService: UserService) {}

  @Post('register') // Endpoint là POST /user/register
  @HttpCode(HttpStatus.CREATED) // Trả về status 201 Created
  async register(@Body() registerUserDto: RegisterUserDto) {
    try {
      const user = await this.userService.register(registerUserDto);
      // Trả về thành công, không trả về password
      return {
        message: 'User registered successfully',
        userId: user._id,
        email: user.email,
      };
    } catch (error) {
      throw error;
    }
  }
}
