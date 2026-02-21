use crate::cli::*;
use crate::generator::ProjectConfig;
use std::path::PathBuf;

pub fn generate(
    project_path: &PathBuf,
    config: &ProjectConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let utils_dir = config.get_utils_dir();
    std::fs::create_dir_all(project_path.join(&utils_dir))?;

    generate_logger(project_path, config, &utils_dir)?;
    generate_response_helper(project_path, config, &utils_dir)?;
    Ok(())
}

fn generate_logger(
    project_path: &PathBuf,
    config: &ProjectConfig,
    utils_dir: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let ext = config.get_ext();
    let config_import = config.get_config_import_path();

    let content = match config.logger {
        LoggerLib::Winston => {
            format!(
                r#"import winston from 'winston';
import {{ config }} from '{config_import}';

const consoleFormat = winston.format.combine(
  winston.format.colorize(),
  winston.format.timestamp({{ format: 'HH:mm:ss' }}),
  winston.format.printf(({{ timestamp, level, message }}) => {{
    return `${{timestamp}} [${{level}}]: ${{message}}`;
  }}),
);

export const logger = winston.createLogger({{
  level: config.logLevel,
  format: winston.format.json(),
  transports: [
    new winston.transports.Console({{
      format: config.nodeEnv === 'development' ? consoleFormat : winston.format.json(),
    }}),
  ],
}});
"#,
                config_import = config_import
            )
        }
        LoggerLib::Pino => {
            format!(
                r#"import pino from 'pino';
import {{ config }} from '{config_import}';

export const logger = pino({{
  level: config.logLevel,
  ...(config.nodeEnv === 'development' ? {{
    transport: {{ target: 'pino-pretty', options: {{ colorize: true }} }},
  }} : {{}}),
}});
"#,
                config_import = config_import
            )
        }
    };

    std::fs::write(project_path.join(format!("{}/logger.{}", utils_dir, ext)), content)?;
    Ok(())
}

fn generate_response_helper(
    project_path: &PathBuf,
    config: &ProjectConfig,
    utils_dir: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let ext = config.get_ext();

    let content = r#"import { Response } from 'express';

export class ApiResponse {
  static success<T>(res: Response, data: T, message = 'Success', statusCode = 200): void {
    res.status(statusCode).json({ success: true, message, data });
  }

  static created<T>(res: Response, data: T, message = 'Created'): void {
    ApiResponse.success(res, data, message, 201);
  }

  static error(res: Response, message: string, statusCode = 500): void {
    res.status(statusCode).json({ success: false, message });
  }

  static paginated<T>(res: Response, data: T[], total: number, page: number, limit: number): void {
    res.json({
      success: true, data,
      pagination: { page, limit, total, pages: Math.ceil(total / limit) },
    });
  }
}
"#;

    std::fs::write(project_path.join(format!("{}/response.{}", utils_dir, ext)), content)?;
    Ok(())
}
