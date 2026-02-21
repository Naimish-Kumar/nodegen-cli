use crate::cli::*;
use crate::generator::ProjectConfig;
use std::path::PathBuf;

pub fn generate(
    project_path: &PathBuf,
    config: &ProjectConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    if config.db.is_none() {
        return Ok(());
    }

    let orm = config.resolve_orm();

    match orm {
        Some(Orm::Mongoose) => generate_mongoose(project_path, config)?,
        Some(Orm::Prisma) => generate_prisma(project_path, config)?,
        Some(Orm::Sequelize) => generate_sequelize(project_path, config)?,
        Some(Orm::Typeorm) => generate_typeorm(project_path, config)?,
        None => {}
    }

    Ok(())
}

fn generate_mongoose(
    project_path: &PathBuf,
    config: &ProjectConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let logger_import = config.get_logger_import_path_from_config();
    let content = format!(
        r#"import mongoose from 'mongoose';
import {{ config }} from './env.config';
import {{ logger }} from '{logger_import}';

export const connectDatabase = async (): Promise<void> => {{
  try {{
    await mongoose.connect(config.databaseUrl, {{
      autoIndex: true,
    }});

    logger.info('📦 MongoDB connected successfully');

    mongoose.connection.on('error', (error) => {{
      logger.error('MongoDB connection error:', error);
    }});

    mongoose.connection.on('disconnected', () => {{
      logger.warn('MongoDB disconnected');
    }});

    // Graceful shutdown
    process.on('SIGINT', async () => {{
      await mongoose.connection.close();
      logger.info('MongoDB connection closed');
      process.exit(0);
    }});
  }} catch (error) {{
    logger.error('Failed to connect to MongoDB:', error);
    process.exit(1);
  }}
}};

export const disconnectDatabase = async (): Promise<void> => {{
  await mongoose.disconnect();
}};
"#,
        logger_import = logger_import
    );

    std::fs::write(
        project_path.join(format!("src/config/database.config.{}", config.get_ext())),
        content,
    )?;

    Ok(())
}

fn generate_prisma(
    project_path: &PathBuf,
    config: &ProjectConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let db = config.db.unwrap();

    let provider = match db {
        Database::Postgres => "postgresql",
        Database::Mysql => "mysql",
        Database::Sqlite => "sqlite",
        Database::Mongodb => "mongodb",
    };

    // prisma/schema.prisma
    let user_model = if config.auth.is_some() {
        r#"
model User {
  id        String   @id @default(cuid())
  email     String   @unique
  password  String
  name      String?
  role      Role     @default(USER)
  isActive  Boolean  @default(true)
  createdAt DateTime @default(now())
  updatedAt DateTime @updatedAt

  @@map("users")
}

enum Role {
  USER
  ADMIN
}
"#
    } else {
        r#"
model User {
  id        String   @id @default(cuid())
  email     String   @unique
  name      String?
  createdAt DateTime @default(now())
  updatedAt DateTime @updatedAt

  @@map("users")
}
"#
    };

    let schema = format!(
        r#"generator client {{
  provider = "prisma-client-js"
}}

datasource db {{
  provider = "{provider}"
  url      = env("DATABASE_URL")
}}
{user_model}"#,
        provider = provider,
        user_model = user_model,
    );

    std::fs::create_dir_all(project_path.join("prisma"))?;
    std::fs::write(project_path.join("prisma/schema.prisma"), schema)?;

    // Database config
    let logger_import = config.get_logger_import_path_from_config();
    let db_config = format!(
        r#"import {{ PrismaClient }} from '@prisma/client';
import {{ logger }} from '{logger_import}';

const prisma = new PrismaClient({{
  log: [
    {{ level: 'query', emit: 'event' }},
    {{ level: 'error', emit: 'stdout' }},
    {{ level: 'warn', emit: 'stdout' }},
  ],
}});

prisma.$on('query', (e) => {{
  if (process.env.NODE_ENV === 'development') {{
    logger.debug(`Query: ${{e.query}} - Duration: ${{e.duration}}ms`);
  }}
}});

export const connectDatabase = async (): Promise<void> => {{
  try {{
    await prisma.$connect();
    logger.info('📦 Database connected successfully (Prisma)');
  }} catch (error) {{
    logger.error('Failed to connect to database:', error);
    process.exit(1);
  }}
}};

export const disconnectDatabase = async (): Promise<void> => {{
  await prisma.$disconnect();
}};

export {{ prisma }};
"#,
        logger_import = logger_import
    );

    std::fs::write(
        project_path.join(format!("src/config/database.config.{}", config.get_ext())),
        db_config,
    )?;

    Ok(())
}

fn generate_sequelize(
    project_path: &PathBuf,
    config: &ProjectConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let db = config.db.unwrap();

    let dialect = match db {
        Database::Postgres => "postgres",
        Database::Mysql => "mysql",
        Database::Sqlite => "sqlite",
        _ => "postgres",
    };

    let logger_import = config.get_logger_import_path_from_config();
    let content = format!(
        r#"import {{ Sequelize }} from 'sequelize';
import {{ config }} from './env.config';
import {{ logger }} from '{logger_import}';

export const sequelize = new Sequelize(config.databaseUrl, {{
  dialect: '{dialect}',
  logging: (msg) => logger.debug(msg),
  pool: {{
    max: 10,
    min: 0,
    acquire: 30000,
    idle: 10000,
  }},
}});

export const connectDatabase = async (): Promise<void> => {{
  try {{
    await sequelize.authenticate();
    logger.info('📦 Database connected successfully (Sequelize)');

    // Sync models in development
    if (config.nodeEnv === 'development') {{
      await sequelize.sync({{ alter: true }});
      logger.info('Database models synchronized');
    }}
  }} catch (error) {{
    logger.error('Failed to connect to database:', error);
    process.exit(1);
  }}
}};

export const disconnectDatabase = async (): Promise<void> => {{
  await sequelize.close();
}};
"#,
        dialect = dialect,
        logger_import = logger_import
    );

    std::fs::write(
        project_path.join(format!("src/config/database.config.{}", config.get_ext())),
        content,
    )?;

    Ok(())
}

fn generate_typeorm(
    project_path: &PathBuf,
    config: &ProjectConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let db = config.db.unwrap();

    let db_type = match db {
        Database::Postgres => "postgres",
        Database::Mysql => "mysql",
        Database::Sqlite => "better-sqlite3",
        _ => "postgres",
    };

    let logger_import = config.get_logger_import_path_from_config();
    let content = format!(
        r#"import {{ DataSource }} from 'typeorm';
import {{ config }} from './env.config';
import {{ logger }} from '{logger_import}';

export const AppDataSource = new DataSource({{
  type: '{db_type}' as any,
  url: config.databaseUrl,
  synchronize: config.nodeEnv === 'development',
  logging: config.nodeEnv === 'development',
  entities: ['src/**/entities/*.ts'],
  migrations: ['src/migrations/*.ts'],
  subscribers: [],
}});

export const connectDatabase = async (): Promise<void> => {{
  try {{
    await AppDataSource.initialize();
    logger.info('📦 Database connected successfully (TypeORM)');
  }} catch (error) {{
    logger.error('Failed to connect to database:', error);
    process.exit(1);
  }}
}};

export const disconnectDatabase = async (): Promise<void> => {{
  await AppDataSource.destroy();
}};
"#,
        db_type = db_type,
        logger_import = logger_import
    );

    std::fs::write(
        project_path.join(format!("src/config/database.config.{}", config.get_ext())),
        content,
    )?;

    Ok(())
}
