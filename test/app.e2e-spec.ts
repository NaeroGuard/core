import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import request from 'supertest';
import { App } from 'supertest/types.js';
import { AppModule } from './../src/app.module.js';

describe('AdblockController (e2e)', () => {
  let app: INestApplication<App>;

  beforeEach(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    await app.init();
  });

  it('POST /api/check blocks a matching URL', async () => {
    const response = await request(app.getHttpServer())
      .post('/api/check')
      .send({
        url: 'https://ads.example.com/pixel',
        custom_rules: ['||ads.example.com^'],
      })
      .expect(200);
    expect(response.body).toEqual({
      blocked: true,
      rule_matched: '||ads.example.com^',
    });
  });

  it('POST /api/check reports a clean URL', async () => {
    const response = await request(app.getHttpServer())
      .post('/api/check')
      .send({
        url: 'https://ok.example.com/',
        custom_rules: ['||ads.example.com^'],
      })
      .expect(200);
    expect(response.body).toEqual({ blocked: false });
  });

  it('POST /api/check rejects an invalid url', () => {
    return request(app.getHttpServer())
      .post('/api/check')
      .send({ url: 'not a url at all' })
      .expect(400);
  });

  it('POST /api/compile-safari returns Safari JSON', async () => {
    const response = await request(app.getHttpServer())
      .post('/api/compile-safari')
      .send({ custom_rules: ['||ads.test^', '@@||ok.test^'] })
      .expect(200);
    expect(response.body).toEqual([
      {
        trigger: { 'url-filter': expect.stringContaining('ads') },
        action: { type: 'block' },
      },
      {
        trigger: { 'url-filter': expect.stringContaining('ok') },
        action: { type: 'ignore-previous-rules' },
      },
    ]);
  });

  afterEach(async () => {
    await app.close();
  });
});
