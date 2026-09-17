import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { createApp } from './app.js';

function fixture() {
  const directory = mkdtempSync(join(tmpdir(), 'monitor-diagnostic-routes-'));
  return createApp({ password: 'correct horse battery staple', authStateFile: join(directory, 'auth-state.json'), sessionSecret: 'diagnostic-route-test-secret-at-least-32-bytes', dataDir: directory, securityStateDir: directory, ssoEnabled: false });
}
describe('diagnostic and notification routes', () => {
  it('requires a session before exposing host/network or security detections', async () => {
    const app = fixture();
    await request(app).get('/monitor/api/network-diagnostics').expect(401);
    await request(app).get('/monitor/api/notification-reports').expect(401);
  });
  it('reports missing observations explicitly for an authenticated user and rejects unbounded queries', async () => {
    const app = fixture();
    const login = await request(app).post('/monitor/api/auth/login').send({ password: 'correct horse battery staple' }).expect(200);
    const cookie = login.headers['set-cookie'];
    expect((await request(app).get('/monitor/api/network-diagnostics').set('Cookie', cookie).expect(200)).body.status).toBe('no_data');
    expect((await request(app).get('/monitor/api/notification-reports').set('Cookie', cookie).expect(200)).body.status).toBe('unavailable');
    await request(app).get('/monitor/api/network-diagnostics?limit=1000000').set('Cookie', cookie).expect(400);
    await request(app).get('/monitor/api/network-diagnostics?path=/etc/passwd').set('Cookie', cookie).expect(400);
  });
});
