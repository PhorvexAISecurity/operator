import 'reflect-metadata';
import { NestFactory } from '@nestjs/core';
import { Body, Controller, Get, Module, Param, Post, Query, Req, Res, HttpCode } from '@nestjs/common';
import express, { Request, Response } from 'express';
import { join } from 'node:path';
import { Config } from './config';
import { Store } from './store';
import { Auth } from './auth';
import { CampaignService } from './campaign';
import { MathLabService } from './mathlab';

@Controller()
class ApiController {
  constructor(private readonly campaigns:CampaignService,private readonly auth:Auth,private readonly math:MathLabService) {}
  @Get('health') health() { return {status:'ok',service:'phorvex-benchmark'}; }
  @Post('api/auth/login') @HttpCode(200) login(@Body() body:any,@Req() request:Request,@Res({passthrough:true}) response:Response) { return this.auth.login(body?.password,request,response); }
  @Post('api/auth/logout') @HttpCode(200) logout(@Req() request:Request,@Res({passthrough:true}) response:Response) { return this.auth.logout(request,response); }
  @Get('api/auth/session') session(@Req() request:Request) { return {authenticated:this.auth.authenticated(request)}; }
  @Get('api/meta') meta(@Req() request:Request) { this.auth.require(request);return this.campaigns.meta(); }
  @Get('api/catalogue') catalogue(@Req() request:Request) { this.auth.require(request);return this.campaigns.catalogue(); }
  @Post('api/plans') plan(@Req() request:Request,@Body() body:unknown) { this.auth.require(request);return this.campaigns.createPlan(body); }
  @Post('api/runs') run(@Req() request:Request,@Body() body:unknown) { this.auth.require(request);return this.campaigns.queue(body); }
  @Get('api/runs') list(@Req() request:Request) { this.auth.require(request);return this.campaigns.list(); }
  @Get('api/runs/:id') detail(@Req() request:Request,@Param('id') id:string) { this.auth.require(request);return this.campaigns.detail(id); }
  @Post('api/runs/:id/cancel') @HttpCode(200) cancel(@Req() request:Request,@Param('id') id:string) { this.auth.require(request);return this.campaigns.cancel(id); }
  @Get('api/runs/:id/events') events(@Req() request:Request,@Param('id') id:string) { this.auth.require(request);return this.campaigns.events(id); }
  @Get('api/runs/:id/artifacts/:name') artifact(@Req() request:Request,@Param('id') id:string,@Param('name') name:string,@Res() response:Response) { this.auth.require(request);const artifact=this.campaigns.artifact(id,name);response.download(artifact.path,artifact.name); }
  // Math/OR Benchmark Lab (read-only replay of recorded decisions; no production write path).
  @Get('api/math/registry') mathRegistry(@Req() request:Request,@Query('policy') policy?:string) { this.auth.require(request);return this.math.registry(policy||undefined); }
  @Get('api/math/policies') mathPolicies(@Req() request:Request) { this.auth.require(request);return this.math.policyStatus(); }
  @Post('api/math/sync') mathSync(@Req() request:Request,@Body() body:unknown) { this.auth.require(request);return this.math.sync(body); }
  @Get('api/math/jobs/:id') mathJob(@Req() request:Request,@Param('id') id:string) { this.auth.require(request);return this.math.job(id); }
  @Post('api/math/experiments/preflight') @HttpCode(200) mathPreflight(@Req() request:Request,@Body() body:unknown) { this.auth.require(request);return this.math.preflight(body); }
  @Post('api/math/experiments') mathCreate(@Req() request:Request,@Body() body:unknown) { this.auth.require(request);return this.math.create(body); }
  @Get('api/math/experiments') mathList(@Req() request:Request) { this.auth.require(request);return this.math.list(); }
  @Get('api/math/experiments/:id') mathDetail(@Req() request:Request,@Param('id') id:string) { this.auth.require(request);return this.math.detail(id); }
  @Get('api/math/experiments/:id/metrics') mathMetrics(@Req() request:Request,@Param('id') id:string) { this.auth.require(request);return this.math.metrics(id); }
  @Get('api/math/experiments/:id/plots') mathPlots(@Req() request:Request,@Param('id') id:string) { this.auth.require(request);return this.math.plots(id); }
  @Get('api/math/experiments/:id/artifacts/*name') mathArtifact(@Req() request:Request,@Param('id') id:string,@Param('name') name:string|string[],@Res() response:Response) { this.auth.require(request);const artifact=this.math.artifact(id,Array.isArray(name)?name.join('/'):name);response.download(artifact.path,artifact.name); }
  @Get('metrics') metrics(@Req() request:Request,@Res() response:Response) { this.auth.metrics(request);response.type('text/plain; version=0.0.4').send(this.campaigns.metrics()); }
}

@Module({controllers:[ApiController],providers:[
  {provide:Config,useFactory:()=>new Config()},
  {provide:Store,inject:[Config],useFactory:(config:Config)=>new Store(join(config.dataDir,'benchmark.sqlite'))},
  {provide:Auth,inject:[Config,Store],useFactory:(config:Config,store:Store)=>new Auth(config,store)},
  {provide:CampaignService,inject:[Config,Store],useFactory:(config:Config,store:Store)=>new CampaignService(config,store)},
  {provide:MathLabService,inject:[Config,Store],useFactory:(config:Config,store:Store)=>new MathLabService(config,store)},
]})
export class AppModule {}

export async function bootstrap() {
  const app=await NestFactory.create(AppModule,{bodyParser:false,logger:['error','warn']});
  app.use(express.json({limit:'32kb',strict:true}));
  app.use((_request:Request,response:Response,next:()=>void)=>{response.setHeader('X-Content-Type-Options','nosniff');response.setHeader('Cache-Control','no-store');next();});
  app.enableShutdownHooks();
  await app.listen(Number(process.env.PORT||4101),process.env.HOST||'127.0.0.1');
  return app;
}
if(require.main===module) void bootstrap().catch(()=>{process.stderr.write('Benchmark API startup failed; check configuration and instance lock.\n');process.exitCode=1;});
