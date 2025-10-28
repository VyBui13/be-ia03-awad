import {
  Injectable,
  ConflictException,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import * as bcrypt from 'bcrypt';
import { User, UserDocument } from './user.schema';
import { RegisterUserDto } from './dto/register-user.dto';
import { JwtService } from '@nestjs/jwt';
import { LoginUserDto } from './dto/login-user.dto';

@Injectable()
export class UserService {
  constructor(
    @InjectModel(User.name) private userModel: Model<UserDocument>,
    private jwtService: JwtService, // 2. Inject JwtService
  ) {}

  async register(registerUserDto: RegisterUserDto): Promise<UserDocument> {
    const { email, password } = registerUserDto;

    // 1. Check for existing email
    const existingUser = await this.userModel.findOne({ email });
    if (existingUser) {
      // 2. Error Handling: Trả về lỗi rõ ràng
      throw new ConflictException('Email already exists');
    }

    // 3. Hash passwords before saving
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // 4. Create new user
    const createdUser = new this.userModel({
      email,
      password: hashedPassword,
      // createdAt sẽ tự động thêm vào [cite: 13]
    });

    return createdUser.save();
  }

  async login(loginUserDto: LoginUserDto): Promise<{ accessToken: string }> {
    const { email, password } = loginUserDto;

    // 1. Tìm user
    const user = await this.userModel.findOne({ email });

    // 2. Kiểm tra user và mật khẩu
    // Dùng chung 1 lỗi "Unauthorized" để bảo mật (tránh lộ thông tin "user không tồn tại")
    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const isPasswordMatching = await bcrypt.compare(password, user.password);

    if (!isPasswordMatching) {
      throw new UnauthorizedException('Invalid credentials');
    }

    // 3. Tạo JWT payload
    const payload = { email: user.email, sub: user._id };

    // 4. Ký và trả về token
    return {
      accessToken: await this.jwtService.signAsync(payload),
    };
  }
}
