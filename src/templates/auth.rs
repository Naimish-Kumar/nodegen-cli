use crate::cli::*;
use crate::generator::ProjectConfig;
use std::path::PathBuf;

pub fn generate(
    project_path: &PathBuf,
    config: &ProjectConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    if config.auth.is_none() {
        return Ok(());
    }

    let auth = config.auth.unwrap();

    // Create auth module directory
    let auth_dir = config.get_controller_path("auth");
    let service_dir = config.get_service_path("auth");
    let route_dir = config.get_route_path("auth");

    std::fs::create_dir_all(project_path.join(&auth_dir))?;
    std::fs::create_dir_all(project_path.join(&service_dir))?;
    std::fs::create_dir_all(project_path.join(&route_dir))?;

    match auth {
        AuthStrategy::Jwt => generate_jwt_auth(project_path, config, &auth_dir)?,
        AuthStrategy::Session => generate_session_auth(project_path, config, &auth_dir)?,
        AuthStrategy::Oauth => generate_oauth_auth(project_path, config, &auth_dir)?,
        AuthStrategy::Firebase => generate_firebase_auth(project_path, config, &auth_dir)?,
    }

    Ok(())
}

fn generate_jwt_auth(
    project_path: &PathBuf,
    config: &ProjectConfig,
    auth_dir: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let ext = config.get_ext();
    let config_import = config.get_config_import_path();
    let error_middleware_import = config.get_error_middleware_import_path_from_module("auth");

    // Auth Controller
    let controller = r#"import { Request, Response, NextFunction } from 'express';
import { AuthService } from './auth.service';

const authService = new AuthService();

export class AuthController {
  async register(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const result = await authService.register(req.body);
      res.status(201).json({
        success: true,
        message: 'User registered successfully',
        data: result,
      });
    } catch (error) {
      next(error);
    }
  }

  async login(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { email, password } = req.body;
      const result = await authService.login(email, password);
      res.json({
        success: true,
        message: 'Login successful',
        data: result,
      });
    } catch (error) {
      next(error);
    }
  }

  async refreshToken(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const { refreshToken } = req.body;
      const result = await authService.refreshToken(refreshToken);
      res.json({
        success: true,
        message: 'Token refreshed successfully',
        data: result,
      });
    } catch (error) {
      next(error);
    }
  }

  async getProfile(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const userId = (req as any).user?.id;
      const user = await authService.getProfile(userId);
      res.json({
        success: true,
        data: user,
      });
    } catch (error) {
      next(error);
    }
  }

  async changePassword(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const userId = (req as any).user?.id;
      const { currentPassword, newPassword } = req.body;
      await authService.changePassword(userId, currentPassword, newPassword);
      res.json({
        success: true,
        message: 'Password changed successfully',
      });
    } catch (error) {
      next(error);
    }
  }
}
"#;

    // Auth Service
    let service = format!(
        r#"import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import {{ config }} from '{config_import}';
import {{ UnauthorizedError, BadRequestError, ConflictError }} from '{error_middleware_import}';

interface UserPayload {{
  id: string;
  email: string;
  role: string;
}}

interface TokenPair {{
  accessToken: string;
  refreshToken: string;
}}

export class AuthService {{
  // In-memory store for demo — replace with database
  private users: any[] = [];

  async register(data: {{ email: string; password: string; name?: string }}): Promise<TokenPair & {{ user: any }}> {{
    const existingUser = this.users.find((u) => u.email === data.email);
    if (existingUser) {{
      throw new ConflictError('User with this email already exists');
    }}

    const hashedPassword = await bcrypt.hash(data.password, 12);

    const user = {{
      id: Date.now().toString(),
      email: data.email,
      name: data.name || '',
      password: hashedPassword,
      role: 'USER',
      createdAt: new Date().toISOString(),
    }};

    this.users.push(user);

    const tokens = this.generateTokens({{ id: user.id, email: user.email, role: user.role }});

    const {{ password, ...userWithoutPassword }} = user;
    return {{ ...tokens, user: userWithoutPassword }};
  }}

  async login(email: string, password: string): Promise<TokenPair & {{ user: any }}> {{
    const user = this.users.find((u) => u.email === email);
    if (!user) {{
      throw new UnauthorizedError('Invalid email or password');
    }}

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {{
      throw new UnauthorizedError('Invalid email or password');
    }}

    const tokens = this.generateTokens({{ id: user.id, email: user.email, role: user.role }});

    const {{ password: _, ...userWithoutPassword }} = user;
    return {{ ...tokens, user: userWithoutPassword }};
  }}

  async refreshToken(refreshToken: string): Promise<TokenPair> {{
    try {{
      const payload = jwt.verify(refreshToken, config.jwtSecret) as UserPayload & {{ type: string }};

      if (payload.type !== 'refresh') {{
        throw new UnauthorizedError('Invalid refresh token');
      }}

      return this.generateTokens({{ id: payload.id, email: payload.email, role: payload.role }});
    }} catch {{
      throw new UnauthorizedError('Invalid or expired refresh token');
    }}
  }}

  async getProfile(userId: string): Promise<any> {{
    const user = this.users.find((u) => u.id === userId);
    if (!user) {{
       throw new UnauthorizedError('User not found');
    }}

    const {{ password, ...userWithoutPassword }} = user;
    return userWithoutPassword;
  }}

  async changePassword(userId: string, currentPassword: string, newPassword: string): Promise<void> {{
    const user = this.users.find((u) => u.id === userId);
    if (!user) {{
      throw new UnauthorizedError('User not found');
    }}

    const isValid = await bcrypt.compare(currentPassword, user.password);
    if (!isValid) {{
      throw new BadRequestError('Current password is incorrect');
    }}

    user.password = await bcrypt.hash(newPassword, 12);
  }}

  private generateTokens(payload: UserPayload): TokenPair {{
    const accessToken = jwt.sign(
      {{ ...payload, type: 'access' }},
      config.jwtSecret,
      {{ expiresIn: config.jwtExpiresIn }},
    );

    const refreshToken = jwt.sign(
      {{ ...payload, type: 'refresh' }},
      config.jwtSecret,
      {{ expiresIn: config.jwtRefreshExpiresIn }},
    );

    return {{ accessToken, refreshToken }};
  }}
}}
"#,
        config_import = config_import,
        error_middleware_import = error_middleware_import
    );

    // Auth Middleware (guard)
    let middleware = format!(
        r#"import {{ Request, Response, NextFunction }} from 'express';
import jwt from 'jsonwebtoken';
import {{ config }} from '{config_import}';
import {{ UnauthorizedError, ForbiddenError }} from '{error_middleware_import}';

interface JWTPayload {{
  id: string;
  email: string;
  role: string;
  type: string;
}}

export const authenticate = (req: Request, _res: Response, next: NextFunction): void => {{
  try {{
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {{
      throw new UnauthorizedError('Access token is required');
    }}

    const token = authHeader.split(' ')[1];

    const payload = jwt.verify(token, config.jwtSecret) as JWTPayload;

    if (payload.type !== 'access') {{
      throw new UnauthorizedError('Invalid token type');
    }}

    (req as any).user = payload;
    next();
  }} catch (error) {{
    if (error instanceof UnauthorizedError) {{
      next(error);
    }} else {{
      next(new UnauthorizedError('Invalid or expired token'));
    }}
  }}
}};

export const authorize = (...roles: string[]) => {{
  return (req: Request, _res: Response, next: NextFunction): void => {{
    const user = (req as any).user;

    if (!user) {{
      next(new UnauthorizedError('Authentication required'));
      return;
    }}

    if (!roles.includes(user.role)) {{
      next(new ForbiddenError('Insufficient permissions'));
      return;
    }}

    next();
  }};
}};
"#,
        config_import = config_import,
        error_middleware_import = error_middleware_import
    );

    let rate_limit_import = error_middleware_import.replace("error.middleware", "rateLimit.middleware");
    // Auth Routes
    let routes = format!(
        r#"import {{ Router }} from 'express';
import {{ AuthController }} from './auth.controller';
import {{ authenticate }} from './auth.middleware';
import {{ authRateLimiter }} from '{rate_limit_import}';

const router = Router();
const authController = new AuthController();

/**
 * @swagger
 * /api/v1/auth/register:
 *   post:
 *     summary: Register a new user
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [email, password]
 *             properties:
 *               email: {{ type: string }}
 *               password: {{ type: string, minLength: 6 }}
 *               name: {{ type: string }}
 */
router.post('/register', authRateLimiter, (req, res, next) =>
  authController.register(req, res, next),
);

/**
 * @swagger
 * /api/v1/auth/login:
 *   post:
 *     summary: Login user
 *     tags: [Auth]
 */
router.post('/login', authRateLimiter, (req, res, next) =>
  authController.login(req, res, next),
);

/**
 * @swagger
 * /api/v1/auth/refresh:
 *   post:
 *     summary: Refresh access token
 *     tags: [Auth]
 */
router.post('/refresh', (req, res, next) =>
  authController.refreshToken(req, res, next),
);

/**
 * @swagger
 * /api/v1/auth/profile:
 *   get:
 *     summary: Get user profile
 *     tags: [Auth]
 *     security: [{{ bearerAuth: [] }}]
 */
router.get('/profile', authenticate, (req, res, next) =>
  authController.getProfile(req, res, next),
);

/**
 * @swagger
 * /api/v1/auth/change-password:
 *   post:
 *     summary: Change password
 *     tags: [Auth]
 *     security: [{{ bearerAuth: [] }}]
 */
router.post('/change-password', authenticate, (req, res, next) =>
  authController.changePassword(req, res, next),
);

export default router;
"#,
        rate_limit_import = rate_limit_import
    );

    // Auth Validators
    let validators = match config.validation {
        ValidationLib::Zod => {
            r#"import { z } from 'zod';

export const registerSchema = z.object({
  body: z.object({
    email: z.string().email('Invalid email format'),
    password: z.string().min(6, 'Password must be at least 6 characters'),
    name: z.string().optional(),
  }),
});

export const loginSchema = z.object({
  body: z.object({
    email: z.string().email('Invalid email format'),
    password: z.string().min(1, 'Password is required'),
  }),
});

export const changePasswordSchema = z.object({
  body: z.object({
    currentPassword: z.string().min(1, 'Current password is required'),
    newPassword: z.string().min(6, 'New password must be at least 6 characters'),
  }),
});
"#
        }
        ValidationLib::Joi => {
            r#"import Joi from 'joi';

export const registerSchema = Joi.object({
  body: Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().min(6).required(),
    name: Joi.string().optional(),
  }),
});

export const loginSchema = Joi.object({
  body: Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().required(),
  }),
});

export const changePasswordSchema = Joi.object({
  body: Joi.object({
    currentPassword: Joi.string().required(),
    newPassword: Joi.string().min(6).required(),
  }),
});
"#
        }
    };

    std::fs::write(project_path.join(format!("{}/auth.controller.{}", auth_dir, ext)), controller)?;
    std::fs::write(project_path.join(format!("{}/auth.service.{}", auth_dir, ext)), service)?;
    std::fs::write(project_path.join(format!("{}/auth.middleware.{}", auth_dir, ext)), middleware)?;
    std::fs::write(project_path.join(format!("{}/auth.routes.{}", auth_dir, ext)), routes)?;
    std::fs::write(project_path.join(format!("{}/auth.validators.{}", auth_dir, ext)), validators)?;

    Ok(())
}

fn generate_session_auth(
    project_path: &PathBuf,
    config: &ProjectConfig,
    auth_dir: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let ext = config.get_ext();
    let config_import = config.get_config_import_path();

    let content = format!(
        r#"import session from 'express-session';
import RedisStore from 'connect-redis';
import {{ config }} from '{config_import}';

// Note: Configure Redis client for production
export const sessionConfig = session({{
  secret: process.env.SESSION_SECRET || 'your-session-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {{
    secure: config.nodeEnv === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    sameSite: 'lax',
  }},
}});
"#,
        config_import = config_import
    );

    std::fs::write(
        project_path.join(format!("{}/session.config.{}", auth_dir, ext)),
        content,
    )?;

    // Also generate basic auth controller and routes
    generate_jwt_auth(project_path, config, auth_dir)?;

    Ok(())
}

fn generate_oauth_auth(
    project_path: &PathBuf,
    config: &ProjectConfig,
    auth_dir: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let ext = config.get_ext();

    let passport_config = r#"import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import { Strategy as GitHubStrategy } from 'passport-github2';

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID || '',
      clientSecret: process.env.GOOGLE_CLIENT_SECRET || '',
      callbackURL: process.env.GOOGLE_CALLBACK_URL || '',
    },
    async (_accessToken, _refreshToken, profile, done) => {
      try {
        // Find or create user from Google profile
        const user = {
          id: profile.id,
          email: profile.emails?.[0]?.value,
          name: profile.displayName,
          provider: 'google',
        };
        done(null, user);
      } catch (error) {
        done(error as Error);
      }
    },
  ),
);

passport.use(
  new GitHubStrategy(
    {
      clientID: process.env.GITHUB_CLIENT_ID || '',
      clientSecret: process.env.GITHUB_CLIENT_SECRET || '',
      callbackURL: process.env.GITHUB_CALLBACK_URL || '',
    },
    async (_accessToken: string, _refreshToken: string, profile: any, done: any) => {
      try {
        const user = {
          id: profile.id,
          email: profile.emails?.[0]?.value,
          name: profile.displayName,
          provider: 'github',
        };
        done(null, user);
      } catch (error) {
        done(error);
      }
    },
  ),
);

passport.serializeUser((user: any, done) => done(null, user));
passport.deserializeUser((user: any, done) => done(null, user));

export default passport;
"#;

    std::fs::write(
        project_path.join(format!("{}/passport.config.{}", auth_dir, ext)),
        passport_config,
    )?;

    // Also generate basic JWT auth for token-based hybrid approach
    generate_jwt_auth(project_path, config, auth_dir)?;

    Ok(())
}

fn generate_firebase_auth(
    project_path: &PathBuf,
    config: &ProjectConfig,
    auth_dir: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let ext = config.get_ext();
    let config_import = config.get_config_import_path();
    let error_middleware_import = config.get_error_middleware_import_path_from_module("auth");

    let firebase_config = r#"import * as admin from 'firebase-admin';

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert({
      projectId: process.env.FIREBASE_PROJECT_ID,
      privateKey: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
    }),
  });
}

export const firebaseAuth = admin.auth();
export const firebaseAdmin = admin;
"#;

    let middleware = format!(
        r#"import {{ Request, Response, NextFunction }} from 'express';
import {{ firebaseAuth }} from './firebase.config';
import {{ UnauthorizedError }} from '{error_middleware_import}';

export const authenticate = async (
  req: Request,
  _res: Response,
  next: NextFunction,
): Promise<void> => {{
  try {{
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {{
      throw new UnauthorizedError('Firebase token is required');
    }}

    const token = authHeader.split(' ')[1];
    const decodedToken = await firebaseAuth.verifyIdToken(token);

    (req as any).user = {{
      id: decodedToken.uid,
      email: decodedToken.email,
      role: decodedToken.role || 'USER',
    }};

    next();
  }} catch (error) {{
    next(new UnauthorizedError('Invalid Firebase token'));
  }}
}};

export const authorize = (...roles: string[]) => {{
  return (req: Request, _res: Response, next: NextFunction): void => {{
    const user = (req as any).user;
    if (!user || !roles.includes(user.role)) {{
      next(new UnauthorizedError('Insufficient permissions'));
      return;
    }}
    next();
  }};
}};
"#,
        error_middleware_import = error_middleware_import
    );

    let routes = r#"import { Router, Request, Response, NextFunction } from 'express';
import { authenticate } from './auth.middleware';

const router = Router();

router.get('/profile', authenticate, (req: Request, res: Response) => {
  res.json({
    success: true,
    data: (req as any).user,
  });
});

export default router;
"#;

    std::fs::write(
        project_path.join(format!("{}/firebase.config.{}", auth_dir, ext)),
        firebase_config,
    )?;
    std::fs::write(
        project_path.join(format!("{}/auth.middleware.{}", auth_dir, ext)),
        middleware,
    )?;
    std::fs::write(
        project_path.join(format!("{}/auth.routes.{}", auth_dir, ext)),
        routes,
    )?;

    Ok(())
}
