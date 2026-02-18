import { body, query, validationResult } from 'express-validator';
import { Request, Response, NextFunction, RequestHandler } from 'express';

function handleValidation(req: Request, res: Response, next: NextFunction): void {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment -- express-validator .msg is typed as any
    const errorMsg: string = errors.array()[0]!.msg;
    res.status(400).json({ error: errorMsg });
    return;
  }
  next();
}

const validateRegister: RequestHandler[] = [
  body('username')
    .trim()
    .isLength({ min: 3, max: 32 })
    .withMessage('Username must be 3-32 characters')
    .matches(/^[a-zA-Z0-9_]+$/)
    .withMessage('Username can only contain letters, numbers, and underscores'),
  body('password')
    .isLength({ min: 12, max: 128 })
    .withMessage('Password must be 12-128 characters')
    .matches(/[a-z]/).withMessage('Password must include a lowercase letter')
    .matches(/[A-Z]/).withMessage('Password must include an uppercase letter')
    .matches(/[0-9]/).withMessage('Password must include a number'),
  handleValidation,
];

const validateLogin: RequestHandler[] = [
  body('username').trim().notEmpty().withMessage('Username is required'),
  body('password').notEmpty().withMessage('Password is required'),
  handleValidation,
];

const validateSearch: RequestHandler[] = [
  query('search').trim().isLength({ min: 2, max: 50 }).withMessage('Search query must be 2-50 characters'),
  handleValidation,
];

export { validateRegister, validateLogin, validateSearch };
