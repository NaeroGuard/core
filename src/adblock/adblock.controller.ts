import { Body, Controller, HttpCode, Post } from '@nestjs/common';
import { AdblockService } from './adblock.service.js';
import type {
  CheckRequest,
  CheckResponse,
  CompileSafariRequest,
  SafariRule,
} from './types.js';

@Controller('api')
export class AdblockController {
  constructor(private readonly adblockService: AdblockService) {}

  @Post('check')
  @HttpCode(200)
  check(@Body() body: CheckRequest): Promise<CheckResponse> {
    return this.adblockService.check(body);
  }

  @Post('compile-safari')
  @HttpCode(200)
  compileSafari(@Body() body: CompileSafariRequest): Promise<SafariRule[]> {
    return this.adblockService.compileSafari(body);
  }
}
