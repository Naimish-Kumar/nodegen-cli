use crate::cli::*;
use crate::generator::ProjectConfig;
use std::path::PathBuf;

pub fn generate(
    project_path: &PathBuf,
    config: &ProjectConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    generate_error_middleware(project_path, config)?;
    generate_logger_middleware(project_path, config)?;
    generate_rate_limit_middleware(project_path, config)?;
    generate_validate_middleware(project_path, config)?;
    Ok(())
}

fn generate_error_middleware(
    project_path: &PathBuf,
    config: &ProjectConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let logger_import = config.get_logger_import_path_from_middleware();
    let content = format!(
        r#"import {{ Request, Response, NextFunction }} from 'express';
import {{ logger }} from '{logger_import}';

export class AppError extends Error {{
  public statusCode: number;
  public isOperational: boolean;

  constructor(message: string, statusCode: number, isOperational = true) {{
    super(message);
    this.statusCode = statusCode;
    this.isOperational = isOperational;
    Object.setPrototypeOf(this, AppError.prototype);
    Error.captureStackTrace(this, this.constructor);
  }}
}}

export class NotFoundError extends AppError {{
  constructor(message = 'Resource not found') {{
    super(message, 404);
  }}
}}

export class BadRequestError extends AppError {{
  constructor(message = 'Bad request') {{
    super(message, 400);
  }}
}}

export class UnauthorizedError extends AppError {{
  constructor(message = 'Unauthorized') {{
    super(message, 401);
  }}
}}

export class ForbiddenError extends AppError {{
  constructor(message = 'Forbidden') {{
    super(message, 403);
  }}
}}

export class ConflictError extends AppError {{
  constructor(message = 'Conflict') {{
    super(message, 409);
  }}
}}

export const errorHandler = (
  err: Error | AppError,
  _req: Request,
  res: Response,
  _next: NextFunction,
): void => {{
  if (err instanceof AppError) {{
    logger.warn(`[${{err.statusCode}}] ${{err.message}}`);
    res.status(err.statusCode).json({{
      success: false,
      message: err.message,
      ...(process.env.NODE_ENV === 'development' && {{ stack: err.stack }}),
    }});
    return;
  }}

  // Unexpected errors
  logger.error('Unexpected error:', err);
  res.status(500).json({{
    success: false,
    message: 'Internal Server Error',
    ...(process.env.NODE_ENV === 'development' && {{
      error: err.message,
      stack: err.stack,
    }}),
  }});
}};
"#,
        logger_import = logger_import
    );

    std::fs::write(
        project_path.join(format!("src/middleware/error.middleware.{}", config.get_ext())),
        content,
    )?;

    Ok(())
}

fn generate_logger_middleware(
    project_path: &PathBuf,
    config: &ProjectConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let logger_import = config.get_logger_import_path_from_middleware();
    let content = format!(
        r#"import {{ Request, Response, NextFunction }} from 'express';
import {{ logger }} from '{logger_import}';

export const requestLogger = (req: Request, res: Response, next: NextFunction): void => {{
  const start = Date.now();

  res.on('finish', () => {{
    const duration = Date.now() - start;
    const logData = {{
      method: req.method,
      url: req.originalUrl,
      statusCode: res.statusCode,
      duration: `${{duration}}ms`,
      ip: req.ip,
      userAgent: req.get('user-agent'),
    }};

    if (res.statusCode >= 400) {{
      logger.warn('Request completed with error', logData);
    }} else {{
      logger.info('Request completed', logData);
    }}
  }});

  next();
}};
"#,
        logger_import = logger_import
    );

    std::fs::write(
        project_path.join(format!(
            "src/middleware/logger.middleware.{}",
            config.get_ext()
        )),
        content,
    )?;

    Ok(())
}

fn generate_rate_limit_middleware(
    project_path: &PathBuf,
    config: &ProjectConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let content = r#"import rateLimit from 'express-rate-limit';
import { config } from '../config/env.config';

export const rateLimiter = rateLimit({
  windowMs: config.rateLimitWindowMs,
  max: config.rateLimitMax,
  message: {
    success: false,
    message: 'Too many requests from this IP, please try again later.',
  },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.ip || 'unknown',
});

export const authRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5,
  message: {
    success: false,
    message: 'Too many authentication attempts, please try again later.',
  },
  standardHeaders: true,
  legacyHeaders: false,
});

export const strictRateLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 10,
  message: {
    success: false,
    message: 'Rate limit exceeded. Please slow down.',
  },
  standardHeaders: true,
  legacyHeaders: false,
});
"#;

    std::fs::write(
        project_path.join(format!(
            "src/middleware/rateLimit.middleware.{}",
            config.get_ext()
        )),
        content,
    )?;

    Ok(())
}

fn generate_validate_middleware(
    project_path: &PathBuf,
    config: &ProjectConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let content = match config.validation {
        ValidationLib::Zod => {
            r#"import { Request, Response, NextFunction } from 'express';
import { ZodSchema, ZodError } from 'zod';

export const validate = (schema: ZodSchema) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    try {
      schema.parse({
        body: req.body,
        query: req.query,
        params: req.params,
      });
      next();
    } catch (error) {
      if (error instanceof ZodError) {
        const errors = error.errors.map((err) => ({
          field: err.path.join('.'),
          message: err.message,
        }));
        res.status(400).json({
          success: false,
          message: 'Validation failed',
          errors,
        });
        return;
      }
      next(error);
    }
  };
};
"#
        }
        ValidationLib::Joi => {
            r#"import { Request, Response, NextFunction } from 'express';
import Joi from 'joi';

export const validate = (schema: Joi.ObjectSchema) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    const { error } = schema.validate(
      {
        body: req.body,
        query: req.query,
        params: req.params,
      },
      { abortEarly: false },
    );

    if (error) {
      const errors = error.details.map((detail) => ({
        field: detail.path.join('.'),
        message: detail.message,
      }));
      res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors,
      });
      return;
    }

    next();
  };
};
"#
        }
    };

    std::fs::write(
        project_path.join(format!(
            "src/middleware/validate.middleware.{}",
            config.get_ext()
        )),
        content,
    )?;

    Ok(())
}
