use crate::cli::*;
use crate::generator::ProjectConfig;
use std::path::PathBuf;

pub fn generate(
    project_path: &PathBuf,
    config: &ProjectConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    generate_env_config(project_path, config)?;
    generate_env_file(project_path, config)?;
    generate_swagger_config(project_path, config)?;
    Ok(())
}

fn generate_env_config(
    project_path: &PathBuf,
    config: &ProjectConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let db_env = if let Some(db) = config.db {
        match db {
            Database::Mongodb => r#"
  databaseUrl: process.env.DATABASE_URL || 'mongodb://localhost:27017/mydb',"#,
            Database::Postgres => r#"
  databaseUrl: process.env.DATABASE_URL || 'postgresql://user:password@localhost:5432/mydb',"#,
            Database::Mysql => r#"
  databaseUrl: process.env.DATABASE_URL || 'mysql://user:password@localhost:3306/mydb',"#,
            Database::Sqlite => r#"
  databaseUrl: process.env.DATABASE_URL || 'file:./dev.db',"#,
        }
    } else {
        ""
    };

    let jwt_env = if matches!(config.auth, Some(AuthStrategy::Jwt) | Some(AuthStrategy::Oauth)) {
        r#"
  jwtSecret: process.env.JWT_SECRET || 'your-super-secret-key-change-in-production',
  jwtExpiresIn: process.env.JWT_EXPIRES_IN || '1h',
  jwtRefreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d',"#
    } else {
        ""
    };

    let content = format!(
        r#"import dotenv from 'dotenv';

dotenv.config();

export const config = {{
  // Server
  port: parseInt(process.env.PORT || '3000', 10),
  nodeEnv: process.env.NODE_ENV || 'development',
  corsOrigin: process.env.CORS_ORIGIN || '*',

  // API
  apiPrefix: process.env.API_PREFIX || '/api/v1',
  apiVersion: process.env.API_VERSION || '1.0.0',{db_env}{jwt_env}

  // Logging
  logLevel: process.env.LOG_LEVEL || 'info',

  // Rate Limiting
  rateLimitMax: parseInt(process.env.RATE_LIMIT_MAX || '100', 10),
  rateLimitWindowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000', 10),
}};
"#,
        db_env = db_env,
        jwt_env = jwt_env,
    );

    std::fs::write(
        project_path.join(format!("src/config/env.config.{}", config.get_ext())),
        content,
    )?;

    Ok(())
}

fn generate_env_file(
    project_path: &PathBuf,
    config: &ProjectConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut env_content = String::from(
        r#"# Server Configuration
NODE_ENV=development
PORT=3000
CORS_ORIGIN=*

# API Configuration
API_PREFIX=/api/v1

# Logging
LOG_LEVEL=info

# Rate Limiting
RATE_LIMIT_MAX=100
RATE_LIMIT_WINDOW_MS=900000
"#,
    );

    if let Some(db) = config.db {
        env_content.push_str("\n# Database\n");
        match db {
            Database::Mongodb => {
                env_content.push_str("DATABASE_URL=mongodb://localhost:27017/mydb\n");
            }
            Database::Postgres => {
                env_content.push_str(
                    "DATABASE_URL=postgresql://user:password@localhost:5432/mydb\n",
                );
            }
            Database::Mysql => {
                env_content.push_str("DATABASE_URL=mysql://user:password@localhost:3306/mydb\n");
            }
            Database::Sqlite => {
                env_content.push_str("DATABASE_URL=file:./dev.db\n");
            }
        }
    }

    if matches!(config.auth, Some(AuthStrategy::Jwt) | Some(AuthStrategy::Oauth)) {
        env_content.push_str(
            r#"
# Authentication
JWT_SECRET=your-super-secret-key-change-in-production
JWT_EXPIRES_IN=1h
JWT_REFRESH_EXPIRES_IN=7d
"#,
        );
    }

    if matches!(config.auth, Some(AuthStrategy::Session)) {
        env_content.push_str(
            r#"
# Session
SESSION_SECRET=your-session-secret-change-in-production
SESSION_MAX_AGE=86400000
REDIS_URL=redis://localhost:6379
"#,
        );
    }

    if matches!(config.auth, Some(AuthStrategy::Firebase)) {
        env_content.push_str(
            r#"
# Firebase
FIREBASE_PROJECT_ID=your-project-id
FIREBASE_PRIVATE_KEY=your-private-key
FIREBASE_CLIENT_EMAIL=your-client-email
"#,
        );
    }

    if matches!(config.auth, Some(AuthStrategy::Oauth)) {
        env_content.push_str(
            r#"
# OAuth
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_CALLBACK_URL=http://localhost:3000/api/v1/auth/google/callback
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret
GITHUB_CALLBACK_URL=http://localhost:3000/api/v1/auth/github/callback
"#,
        );
    }

    std::fs::write(project_path.join(".env.example"), &env_content)?;
    std::fs::write(project_path.join(".env"), &env_content)?;

    Ok(())
}

fn generate_swagger_config(
    project_path: &PathBuf,
    config: &ProjectConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    if config.framework == Framework::Express {
        let content = format!(
            r#"import swaggerJSDoc from 'swagger-jsdoc';

const swaggerDefinition = {{
  openapi: '3.0.0',
  info: {{
    title: '{name} API',
    version: '1.0.0',
    description: 'API documentation for {name}',
    contact: {{
      name: 'API Support',
    }},
  }},
  servers: [
    {{
      url: 'http://localhost:3000/api/v1',
      description: 'Development server',
    }},
  ],
  components: {{
    securitySchemes: {{
      bearerAuth: {{
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
      }},
    }},
  }},
}};

const options: swaggerJSDoc.Options = {{
  swaggerDefinition,
  apis: ['./src/**/*.ts'],
}};

export const swaggerSpec = swaggerJSDoc(options);
"#,
            name = config.name,
        );

        std::fs::write(
            project_path.join(format!("src/config/swagger.config.{}", config.get_ext())),
            content,
        )?;
    }

    Ok(())
}
