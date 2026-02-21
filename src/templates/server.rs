use crate::cli::*;
use crate::generator::ProjectConfig;
use std::path::PathBuf;

pub fn generate(
    project_path: &PathBuf,
    config: &ProjectConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    match config.framework {
        Framework::Express => generate_express_server(project_path, config)?,
        Framework::Fastify => generate_fastify_server(project_path, config)?,
        Framework::Nest => generate_nest_server(project_path, config)?,
    }
    Ok(())
}

fn generate_express_server(
    project_path: &PathBuf,
    config: &ProjectConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let app_import = config.get_app_import_path();
    let config_import = config.get_env_config_import_path_from_src();
    let logger_import = config.get_logger_import_path();

    let content = format!(
        r#"import app from '{app_import}';
import {{ config }} from '{config_import}';
import {{ logger }} from '{logger_import}';

const startServer = async (): Promise<void> => {{
  try {{
    await app.initialize();

    app.app.listen(config.port, () => {{
      logger.info(`🚀 Server running on port ${{config.port}}`);
      logger.info(`📖 API Docs: http://localhost:${{config.port}}/api-docs`);
      logger.info(`🏥 Health: http://localhost:${{config.port}}/health`);
      logger.info(`🌍 Environment: ${{config.nodeEnv}}`);
    }});
  }} catch (error) {{
    logger.error('Failed to start server:', error);
    process.exit(1);
  }}
}};

// Graceful shutdown
const gracefulShutdown = (signal: string): void => {{
  logger.info(`${{signal}} received. Starting graceful shutdown...`);
  process.exit(0);
}};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));
process.on('uncaughtException', (error) => {{
  logger.error('Uncaught Exception:', error);
  process.exit(1);
}});
process.on('unhandledRejection', (reason) => {{
  logger.error('Unhandled Rejection:', reason);
  process.exit(1);
}});

startServer();
"#,
        app_import = app_import,
        config_import = config_import,
        logger_import = logger_import
    );

    std::fs::write(
        project_path.join(format!("src/server.{}", config.get_ext())),
        content,
    )?;

    Ok(())
}

fn generate_fastify_server(
    project_path: &PathBuf,
    config: &ProjectConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let app_import = config.get_app_import_path();
    let config_import = config.get_env_config_import_path_from_src();
    let logger_import = config.get_logger_import_path();

    let content = format!(
        r#"import app from '{app_import}';
import {{ config }} from '{config_import}';
import {{ logger }} from '{logger_import}';

const startServer = async (): Promise<void> => {{
  try {{
    await app.initialize();

    await app.app.listen({{ port: config.port, host: '0.0.0.0' }});

    logger.info(`🚀 Fastify server running on port ${{config.port}}`);
    logger.info(`📖 API Docs: http://localhost:${{config.port}}/api-docs`);
    logger.info(`🏥 Health: http://localhost:${{config.port}}/health`);
    logger.info(`🌍 Environment: ${{config.nodeEnv}}`);
  }} catch (error) {{
    logger.error('Failed to start server:', error);
    process.exit(1);
  }}
}};

// Graceful shutdown
const gracefulShutdown = async (signal: string): Promise<void> => {{
  logger.info(`${{signal}} received. Starting graceful shutdown...`);
  await app.app.close();
  process.exit(0);
}};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

startServer();
"#,
        app_import = app_import,
        config_import = config_import,
        logger_import = logger_import
    );

    std::fs::write(
        project_path.join(format!("src/server.{}", config.get_ext())),
        content,
    )?;

    Ok(())
}

fn generate_nest_server(
    project_path: &PathBuf,
    config: &ProjectConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let app_module_import = "./app.module";
    let config_import = config.get_env_config_import_path_from_src();
    let logger_import = config.get_logger_import_path();

    let content = format!(
        r#"import {{ NestFactory }} from '@nestjs/core';
import {{ AppModule }} from '{app_module_import}';
import {{ config }} from '{config_import}';
import {{ logger }} from '{logger_import}';

async function bootstrap(): Promise<void> {{
  const app = await NestFactory.create(AppModule);

  app.enableCors({{
    origin: config.corsOrigin,
    credentials: true,
  }});

  app.setGlobalPrefix('api/v1');

  await app.listen(config.port);

  logger.info(`🚀 NestJS server running on port ${{config.port}}`);
  logger.info(`🌍 Environment: ${{config.nodeEnv}}`);
}}

bootstrap();
"#,
        app_module_import = app_module_import,
        config_import = config_import,
        logger_import = logger_import
    );

    std::fs::write(
        project_path.join(format!("src/server.{}", config.get_ext())),
        content,
    )?;

    Ok(())
}
