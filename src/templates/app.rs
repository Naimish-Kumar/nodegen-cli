use crate::cli::*;
use crate::generator::ProjectConfig;
use std::path::PathBuf;

pub fn generate(
    project_path: &PathBuf,
    config: &ProjectConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    match config.framework {
        Framework::Express => generate_express_app(project_path, config)?,
        Framework::Fastify => generate_fastify_app(project_path, config)?,
        Framework::Nest => generate_nest_app(project_path, config)?,
    }
    Ok(())
}

fn generate_express_app(
    project_path: &PathBuf,
    config: &ProjectConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let ext = config.get_ext();
    let config_import = config.get_env_config_import_path_from_src();
    let logger_import = config.get_logger_import_path();

    let _validation_import = match config.validation {
        ValidationLib::Zod => "",
        ValidationLib::Joi => "",
    };

    let swagger_setup = format!(
        "\nimport swaggerUi from 'swagger-ui-express';\nimport {{ swaggerSpec }} from './config/swagger.config';"
    );

    let swagger_routes = r#"
    // Swagger Documentation
    this.app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));
"#;

    let auth_import = if config.auth.is_some() {
        match config.arch {
            Architecture::Modular => "\nimport authRoutes from './modules/auth/routes/auth.routes';",
            _ => "\nimport authRoutes from './modules/auth/auth.routes';",
        }
    } else {
        ""
    };

    let auth_route = if config.auth.is_some() {
        "\n    this.app.use('/api/v1/auth', authRoutes);"
    } else {
        ""
    };

    let db_import = if config.db.is_some() {
        "\nimport { connectDatabase } from './config/database.config';"
    } else {
        ""
    };

    let db_connect = if config.db.is_some() {
        "\n    await connectDatabase();"
    } else {
        ""
    };

    let content = format!(
        r#"import express, {{ Application }} from 'express';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import hpp from 'hpp';
import {{ config }} from '{config_import}';
import {{ errorHandler }} from './middleware/error.middleware';
import {{ requestLogger }} from './middleware/logger.middleware';
import {{ rateLimiter }} from './middleware/rateLimit.middleware';
import {{ apiRoutes }} from './routes';
import {{ logger }} from '{logger_import}';{swagger_setup}{auth_import}{db_import}

class App {{
  public app: Application;

  constructor() {{
    this.app = express();
    this.initializeMiddlewares();
    this.initializeRoutes();
    this.initializeErrorHandling();
  }}

  private initializeMiddlewares(): void {{
    // Security
    this.app.use(helmet());
    this.app.use(hpp());
    this.app.use(cors({{
      origin: config.corsOrigin,
      credentials: true,
    }}));

    // Compression & Parsing
    this.app.use(compression());
    this.app.use(express.json({{ limit: '10mb' }}));
    this.app.use(express.urlencoded({{ extended: true }}));

    // Rate limiting
    this.app.use(rateLimiter);

    // Logging
    this.app.use(requestLogger);
  }}

  private initializeRoutes(): void {{
    // Health check
    this.app.get('/health', (_req, res) => {{
      res.json({{
        status: 'OK',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
      }});
    }});

    // API Routes
    this.app.use('/api/v1', apiRoutes);{auth_route}{swagger_routes}
  }}

  private initializeErrorHandling(): void {{
    this.app.use(errorHandler);
  }}

  public async initialize(): Promise<void> {{{db_connect}
    logger.info('Application initialized successfully');
  }}
}}

export default new App();
"#,
        config_import = config_import,
        logger_import = logger_import,
        swagger_setup = swagger_setup,
        auth_import = auth_import,
        auth_route = auth_route,
        db_import = db_import,
        db_connect = db_connect,
        swagger_routes = swagger_routes,
    );

    std::fs::write(
        project_path.join(format!("src/app.{}", ext)),
        content,
    )?;

    Ok(())
}

fn generate_fastify_app(
    project_path: &PathBuf,
    config: &ProjectConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let db_import = if config.db.is_some() {
        "\nimport { connectDatabase } from './config/database.config';"
    } else {
        ""
    };

    let db_connect = if config.db.is_some() {
        "\n    await connectDatabase();"
    } else {
        ""
    };

    let content = format!(
        r#"import Fastify, {{ FastifyInstance }} from 'fastify';
import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import rateLimit from '@fastify/rate-limit';
import swagger from '@fastify/swagger';
import swaggerUi from '@fastify/swagger-ui';
import {{ config }} from './config/env.config';
import {{ logger }} from './utils/logger';{db_import}

class App {{
  public app: FastifyInstance;

  constructor() {{
    this.app = Fastify({{
      logger: false,
    }});
  }}

  public async initialize(): Promise<void> {{
    await this.registerPlugins();
    await this.registerRoutes();{db_connect}
    logger.info('Fastify application initialized');
  }}

  private async registerPlugins(): Promise<void> {{
    // CORS
    await this.app.register(cors, {{
      origin: config.corsOrigin,
      credentials: true,
    }});

    // Security headers
    await this.app.register(helmet);

    // Rate limiting
    await this.app.register(rateLimit, {{
      max: 100,
      timeWindow: '15 minutes',
    }});

    // Swagger
    await this.app.register(swagger, {{
      openapi: {{
        info: {{
          title: '{name} API',
          version: '1.0.0',
          description: 'API Documentation',
        }},
        servers: [{{ url: `http://localhost:${{config.port}}` }}],
      }},
    }});

    await this.app.register(swaggerUi, {{
      routePrefix: '/api-docs',
    }});
  }}

  private async registerRoutes(): Promise<void> {{
    // Health check
    this.app.get('/health', async () => ({{
      status: 'OK',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
    }}));
  }}
}}

export default new App();
"#,
        name = config.name,
        db_import = db_import,
        db_connect = db_connect,
    );

    std::fs::write(
        project_path.join(format!("src/app.{}", config.get_ext())),
        content,
    )?;

    Ok(())
}

fn generate_nest_app(
    project_path: &PathBuf,
    config: &ProjectConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let content = r#"import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';

@Module({
  imports: [],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
"#;

    std::fs::write(
        project_path.join(format!("src/app.module.{}", config.get_ext())),
        content,
    )?;

    let controller = r#"import { Controller, Get } from '@nestjs/common';
import { AppService } from './app.service';

@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Get('health')
  getHealth() {
    return this.appService.getHealth();
  }
}
"#;

    std::fs::write(
        project_path.join(format!("src/app.controller.{}", config.get_ext())),
        controller,
    )?;

    let service = r#"import { Injectable } from '@nestjs/common';

@Injectable()
export class AppService {
  getHealth() {
    return {
      status: 'OK',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
    };
  }
}
"#;

    std::fs::write(
        project_path.join(format!("src/app.service.{}", config.get_ext())),
        service,
    )?;

    Ok(())
}
