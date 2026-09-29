import { Body, Controller, Delete, Get, Param, Post, Put, UploadedFile, UseInterceptors, UsePipes, ValidationPipe, NotFoundException, UseGuards, Req, Patch, HttpException } from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import { diskStorage, MulterError } from 'multer';
import { extname } from 'path';
import { UsersService } from './users.service';
import { CreateUserDto } from './createUsers.dto';
import { UpdateUserDto } from './updateUsers.dto';
import { JwtService } from '@nestjs/jwt';

import { access } from 'fs';
import { UserGuard } from './user.guard';
import { LoginDto } from './login.dto';
import { ChangePasswordDto } from './change-password.dto';

@Controller('users')
export class UsersController {
  constructor(
    private readonly userService: UsersService,
    private readonly jwtService: JwtService
  ) { }

  @Post()
  @UsePipes(new ValidationPipe({ whitelist: true, transform: true }))
  createUser(@Body() user: CreateUserDto) {
    return this.userService.createUser(user);
  }

  @UseGuards(UserGuard)
  @Get()
  findAll() {
    return this.userService.findAll();
  }

  @UseGuards(UserGuard)
  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.userService.findOne(id);
  }

  @UseGuards(UserGuard)
  @Put(':id')
  @UsePipes(new ValidationPipe({ whitelist: true, transform: true }))
  update(@Param('id') id: string, @Body() data: UpdateUserDto) {
    return this.userService.update(id, data);
  }

  @UseGuards(UserGuard)
  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.userService.remove(id);
  }

  @UseGuards(UserGuard)
  @Post(':id/upload-image')
  @UseInterceptors(FileInterceptor('file', {
    fileFilter: (req, file, cb) => {
      if (file.originalname.match(/^.*\.(jpg|webp|png|jpeg)$/)) cb(null, true);
      else {
        cb(new MulterError('LIMIT_UNEXPECTED_FILE', 'image'), false);
      }
    },
    limits: { fileSize: 30000 }, storage: diskStorage({
      destination: './uploads',
      filename: function (req, file, cb) {
        cb(null, Date.now() + file.originalname)
      },
    })
  }))
  uploadProfileImage(@Param('id') id: string, @UploadedFile() file: Express.Multer.File) {
    return this.userService.updateProfileImage(id, file?.filename);
  }

  @Post('login')
  @UsePipes(new ValidationPipe({ whitelist: true, transform: true }))
  async login(@Body() credentials: LoginDto) {
    const user = await this.userService.validateUser(credentials.email, credentials.password);
    if (!user) {
      throw new HttpException('Invalid credentials', 401);
    }

    // Return user data without password
    const payload = { sub: user.userID, email: user.email, role: user.role };
    return {
      access_token: await this.jwtService.signAsync(payload, { expiresIn: '6h' }),
    }
  }

  @UseGuards(UserGuard)
  @Post(':id/change-password')
  @UsePipes(new ValidationPipe({ whitelist: true, transform: true }))
  async changePassword(
    @Param('id') id: string,
    @Body() data: ChangePasswordDto
  ) {
    const success = await this.userService.changePassword(
      id,
      data.currentPassword,
      data.newPassword
    );

    if (!success) {
      throw new HttpException('Current password is incorrect', 400);
    }

    return { message: 'Password changed successfully' };
  }

}
