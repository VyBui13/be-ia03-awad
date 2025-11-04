import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { UserService } from 'src/user/user.service';
import { LoginUserDto } from './dto/login-user.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthService {
  constructor(
    private userService: UserService, // <--- 2. Inject UserService
    private jwtService: JwtService,
    private configService: ConfigService,
  ) {}

  // HÀM 1: LOGIN
  async login(loginDto: LoginUserDto) {
    // 1. Tìm user
    const user = await this.userService.findByEmail(loginDto.email);
    if (!user) {
      throw new UnauthorizedException('Email hoặc mật khẩu không đúng');
    }

    // 2. So sánh mật khẩu
    const isPasswordMatching = await bcrypt.compare(
      loginDto.password,
      user.password,
    );
    if (!isPasswordMatching) {
      throw new UnauthorizedException('Email hoặc mật khẩu không đúng');
    }

    return this.generateTokens(user);
  }

  async refreshToken(refreshTokenDto: RefreshTokenDto) {
    try {
      const payload = await this.jwtService.verifyAsync(
        refreshTokenDto.refreshToken,
        {
          secret: this.configService.get('JWT_REFRESH_SECRET'),
        },
      );

      const accessTokenPayload = { sub: payload.sub, email: payload.email };
      const accessToken = await this.jwtService.signAsync(accessTokenPayload);
      return { accessToken };
    } catch (e) {
      throw new UnauthorizedException(
        'Refresh token không hợp lệ hoặc đã hết hạn',
      );
    }
  }

  private async generateTokens(user: any) {
    const payload = { email: user.email, sub: user.id }; // 'sub' là viết tắt của 'subject', thường dùng để lưu ID

    const [accessToken, refreshToken] = await Promise.all([
      // Access Token
      this.jwtService.signAsync(payload), // Dùng secret và thời hạn mặc định (JWT_SECRET, 15m)

      // Refresh Token
      this.jwtService.signAsync(payload, {
        secret: this.configService.get('JWT_REFRESH_SECRET'), // Dùng secret riêng
        expiresIn: this.configService.get('REFRESH_TOKEN_EXPIRATION'), // Dùng thời hạn riêng (7d)
      }),
    ]);

    return {
      accessToken,
      refreshToken,
    };
  }
}
