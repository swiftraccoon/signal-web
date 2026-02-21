import express, { Request, Response } from 'express';
import logger from '../logger';
import { cspReportLimiter } from '../middleware/rateLimiter';

const router = express.Router();

// Unauthenticated, aggressively rate-limited
// CSP reports use Content-Type: application/csp-report
router.post('/csp-report', cspReportLimiter,
  express.json({ type: ['application/csp-report', 'application/json'], limit: '4kb' }),
  (req: Request, res: Response) => {
    const report = req.body as Record<string, unknown>;
    if (report && typeof report === 'object') {
      logger.warn({ cspReport: report }, 'CSP violation');
    }
    res.status(204).end();
  }
);

export default router;
