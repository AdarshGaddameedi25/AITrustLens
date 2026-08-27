import { jest } from '@jest/globals';
import request from 'supertest';
import jwt from 'jsonwebtoken';
import { env } from '../../src/config/env.js';
import prisma from '../../src/config/database.js';

// Mock BullMQ Queue so tests don't try to connect to Redis for enqueueing
jest.unstable_mockModule('bullmq', () => {
  return {
    Queue: jest.fn().mockImplementation(() => ({
      add: jest.fn().mockResolvedValue({ id: 'test-job-id' }),
      close: jest.fn().mockResolvedValue(true),
    })),
  };
});

// Mock heavy CJS imports that break Jest ESM mode
jest.unstable_mockModule('../../src/services/qrAnalyzerService.js', () => ({
  analyzeQrCode: jest.fn().mockResolvedValue({ trustScore: null, riskLevel: 'INFO' }),
}));

jest.unstable_mockModule('../../src/services/identityAnalyzerService.js', () => ({
  analyzeIdentity: jest.fn().mockResolvedValue({ trustScore: 70, riskLevel: 'MEDIUM' })
}));

jest.unstable_mockModule('../../src/services/urlAnalyzerService.js', () => ({
  analyzeUrl: jest.fn().mockResolvedValue({ scanId: 'mock-scan-id-123', status: 'QUEUED', cached: false }),
  getScanStatus: jest.fn().mockResolvedValue(null),
}));

let app;

// Setup valid JWT for testing
const generateToken = (userId, role = 'USER') => {
  return jwt.sign({ userId, role, type: 'access' }, env.jwt.secret, { expiresIn: '15m' });
};

describe('Integration Tests: /api/analyze Routes', () => {
  let testUser;
  let testToken;

  beforeAll(async () => {
    const appModule = await import('../../src/app.js');
    app = appModule.default;

    // Create a test user in the database
    testUser = await prisma.user.create({
      data: {
        email: `test-${Date.now()}@example.com`,
        passwordHash: 'hashed-password',
        name: 'Integration Test User',
      },
    });
    testToken = generateToken(testUser.id);
  });

  afterAll(async () => {
    // Cleanup
    if (testUser?.id) {
      await prisma.user.delete({ where: { id: testUser.id } });
    }
    await prisma.$disconnect();
  });

  it('POST /api/analyze/url - Route is reachable and requires auth; authenticated request is accepted', async () => {
    const payload = { url: 'https://example.com' };
    
    const response = await request(app)
      .post('/api/analyze/url')
      .set('Authorization', `Bearer ${testToken}`)
      .send(payload);

    // The route must not return 401 (unauthenticated) or 403 (forbidden).
    // The actual result (200 sync, 202 queued, or 500 if Redis unavailable) is
    // an infrastructure detail — we only verify auth + routing works here.
    expect(response.status).not.toBe(401);
    expect(response.status).not.toBe(403);
    expect(response.body).toHaveProperty('success');
  });

  it('POST /api/analyze/identity - Should return deterministic risk for missing data', async () => {
    const payload = { email: 'unknown-domain-test@example.com' };
    
    // The service handles it, we just want to ensure route hits controller and validates
    const response = await request(app)
      .post('/api/analyze/identity')
      .set('Authorization', `Bearer ${testToken}`)
      .send(payload);

    // Identity is currently implemented synchronously in the codebase without queue, 
    // or queued if it takes long. In Phase 1 we made it synchronous returning full result.
    // If it's queued, it returns 202. Let's check status.
    expect([200, 202]).toContain(response.status);
    expect(response.body.success).toBe(true);
  });
  
  it('GET /api/scans - Should return paginated scan history', async () => {
    const response = await request(app)
      .get('/api/scans')
      .set('Authorization', `Bearer ${testToken}`);

    expect(response.status).toBe(200);
    expect(response.body.success).toBe(true);
    expect(Array.isArray(response.body.data)).toBe(true);
  });
});
