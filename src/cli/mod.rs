use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(
    name = "node-project-gen",
    version,
    about = "⚡ Lightning-fast Node.js backend generator",
    long_about = "Acrocoder - Generate production-ready Node.js backends in seconds.\n\nBuilt with Rust for blazing fast scaffolding.",
    after_help = "Examples:\n  node-project-gen create my_api --arch clean --db postgres --auth jwt\n  node-project-gen create my_api --arch mvc --framework fastify --db mongodb\n  node-project-gen generate module auth\n  node-project-gen add docker"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Create a new Node.js backend project
    #[command(alias = "new")]
    Create {
        name: String,
        #[arg(long, short, value_enum, default_value = "modular")]
        arch: Architecture,
        #[arg(long, short, value_enum, default_value = "express")]
        framework: Framework,
        #[arg(long, short, value_enum)]
        db: Option<Database>,
        #[arg(long, value_enum)]
        auth: Option<AuthStrategy>,
        #[arg(long, value_enum)]
        orm: Option<Orm>,
        #[arg(long, value_enum, default_value = "jest")]
        test: TestFramework,
        #[arg(long, value_enum, default_value = "zod")]
        validation: ValidationLib,
        #[arg(long, value_enum, default_value = "winston")]
        logger: LoggerLib,
        #[arg(long, default_value = "true")]
        typescript: bool,
        #[arg(long)]
        skip_install: bool,
        #[arg(long, default_value = "true")]
        git: bool,
    },
    /// Generate a module, resource, or component
    Generate {
        #[command(subcommand)]
        what: GenerateTarget,
    },
    /// Add features to an existing project
    Add {
        #[command(subcommand)]
        feature: AddFeature,
    },
}

#[derive(Subcommand)]
pub enum GenerateTarget {
    Module { name: String, #[arg(long)] crud: bool },
    Resource { name: String },
    Middleware { name: String },
}

#[derive(Subcommand)]
pub enum AddFeature {
    Docker, Swagger, Cicd, Websocket, Ratelimit,
    Testing { #[arg(long, value_enum, default_value = "jest")] framework: TestFramework },
}

#[derive(Clone, Copy, ValueEnum, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum Architecture { Clean, Mvc, Modular, Hexagonal, Microservice }

impl std::fmt::Display for Architecture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Architecture::Clean => write!(f, "clean"),
            Architecture::Mvc => write!(f, "mvc"),
            Architecture::Modular => write!(f, "modular"),
            Architecture::Hexagonal => write!(f, "hexagonal"),
            Architecture::Microservice => write!(f, "microservice"),
        }
    }
}

#[derive(Clone, Copy, ValueEnum, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum Framework { Express, Fastify, Nest }

impl std::fmt::Display for Framework {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self { Framework::Express => write!(f, "express"), Framework::Fastify => write!(f, "fastify"), Framework::Nest => write!(f, "nest") }
    }
}

#[derive(Clone, Copy, ValueEnum, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum Database { Mongodb, Postgres, Mysql, Sqlite }

impl std::fmt::Display for Database {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self { Database::Mongodb => write!(f, "mongodb"), Database::Postgres => write!(f, "postgres"), Database::Mysql => write!(f, "mysql"), Database::Sqlite => write!(f, "sqlite") }
    }
}

#[derive(Clone, Copy, ValueEnum, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum AuthStrategy { Jwt, Session, Oauth, Firebase }

impl std::fmt::Display for AuthStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self { AuthStrategy::Jwt => write!(f, "jwt"), AuthStrategy::Session => write!(f, "session"), AuthStrategy::Oauth => write!(f, "oauth"), AuthStrategy::Firebase => write!(f, "firebase") }
    }
}

#[derive(Clone, Copy, ValueEnum, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum Orm { Prisma, Sequelize, Mongoose, Typeorm }

impl std::fmt::Display for Orm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self { Orm::Prisma => write!(f, "prisma"), Orm::Sequelize => write!(f, "sequelize"), Orm::Mongoose => write!(f, "mongoose"), Orm::Typeorm => write!(f, "typeorm") }
    }
}

#[derive(Clone, Copy, ValueEnum, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum TestFramework { Jest, Vitest }

impl std::fmt::Display for TestFramework {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self { TestFramework::Jest => write!(f, "jest"), TestFramework::Vitest => write!(f, "vitest") }
    }
}

#[derive(Clone, Copy, ValueEnum, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum ValidationLib { Zod, Joi }

impl std::fmt::Display for ValidationLib {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self { ValidationLib::Zod => write!(f, "zod"), ValidationLib::Joi => write!(f, "joi") }
    }
}

#[derive(Clone, Copy, ValueEnum, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum LoggerLib { Winston, Pino }

impl std::fmt::Display for LoggerLib {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self { LoggerLib::Winston => write!(f, "winston"), LoggerLib::Pino => write!(f, "pino") }
    }
}

pub fn handle_command(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    match cli.command {
        Commands::Create { name, arch, framework, db, auth, orm, test, validation, logger, typescript, skip_install, git } => {
            let config = crate::generator::ProjectConfig { name, arch, framework, db, auth, orm, test, validation, logger, typescript, skip_install, git };
            crate::generator::create_project(config)?;
        }
        Commands::Generate { what } => {
            crate::generator::additions::handle_generate(what)?;
        }
        Commands::Add { feature } => {
            crate::generator::additions::handle_add(feature)?;
        }
    }
    Ok(())
}
