pub mod additions;
pub mod structure;

use crate::cli::*;
use crate::templates;
use crate::utils::printer;
use std::path::PathBuf;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProjectConfig {
    pub name: String,
    pub arch: Architecture,
    pub framework: Framework,
    pub db: Option<Database>,
    pub auth: Option<AuthStrategy>,
    pub orm: Option<Orm>,
    pub test: TestFramework,
    pub validation: ValidationLib,
    pub logger: LoggerLib,
    pub typescript: bool,
    pub skip_install: bool,
    pub git: bool,
}

impl ProjectConfig {
    pub fn resolve_orm(&self) -> Option<Orm> {
        if let Some(orm) = self.orm {
            return Some(orm);
        }
        self.db.map(|db| match db {
            Database::Mongodb => Orm::Mongoose,
            Database::Postgres | Database::Mysql | Database::Sqlite => Orm::Prisma,
        })
    }

    pub fn get_ext(&self) -> &str {
        if self.typescript { "ts" } else { "js" }
    }

    pub fn get_controller_path(&self, module: &str) -> String {
        match self.arch {
            Architecture::Clean => format!("src/presentation/controllers/{}", module),
            Architecture::Mvc => "src/controllers".to_string(),
            Architecture::Modular => format!("src/modules/{}/controllers", module),
            Architecture::Hexagonal => "src/adapters/inbound/http/controllers".to_string(),
            Architecture::Microservice => format!("services/{}/src/controllers", module),
        }
    }

    pub fn get_route_path(&self, module: &str) -> String {
        match self.arch {
            Architecture::Clean => format!("src/presentation/routes/{}", module),
            Architecture::Mvc => "src/routes".to_string(),
            Architecture::Modular => format!("src/modules/{}/routes", module),
            Architecture::Hexagonal => "src/adapters/inbound/http/routes".to_string(),
            Architecture::Microservice => format!("services/{}/src/routes", module),
        }
    }

    pub fn get_service_path(&self, module: &str) -> String {
        match self.arch {
            Architecture::Clean => format!("src/application/services/{}", module),
            Architecture::Mvc => "src/services".to_string(),
            Architecture::Modular => format!("src/modules/{}/services", module),
            Architecture::Hexagonal => "src/domain/services".to_string(),
            Architecture::Microservice => format!("services/{}/src/services", module),
        }
    }

    pub fn get_module_root(&self, module: &str) -> String {
        match self.arch {
            Architecture::Clean => format!("src/presentation/controllers/{}", module), // Using controller as root for Clean
            Architecture::Mvc => "src".to_string(),
            Architecture::Modular => format!("src/modules/{}", module),
            Architecture::Hexagonal => "src/adapters/inbound/http/controllers".to_string(),
            Architecture::Microservice => format!("services/{}/src", module),
        }
    }

    pub fn get_service_import_path(&self, module: &str) -> String {
        match self.arch {
            Architecture::Clean => format!("../../../application/services/{}/{}", module, module),
            Architecture::Mvc => format!("../services/{}", module),
            Architecture::Modular => format!("../services/{}", module),
            Architecture::Hexagonal => format!("../../../../../domain/services/{}", module),
            Architecture::Microservice => format!("../services/{}", module),
        }
    }

    pub fn get_utils_import_path(&self, _module: &str) -> String {
        match self.arch {
            Architecture::Clean => "../../../../utils/response".to_string(),
            Architecture::Mvc => "../../utils/response".to_string(),
            Architecture::Modular => "../../../shared/utils/response".to_string(),
            Architecture::Hexagonal => "../../../../../../utils/response".to_string(),
            Architecture::Microservice => "../../utils/response".to_string(),
        }
    }

    pub fn get_utils_dir(&self) -> String {
        match self.arch {
            Architecture::Modular => "src/shared/utils".to_string(),
            _ => "src/utils".to_string(),
        }
    }

    pub fn get_config_import_path(&self) -> String {
        match self.arch {
            Architecture::Modular => "../../config/env.config".to_string(),
            _ => "../config/env.config".to_string(),
        }
    }

    pub fn get_app_import_path(&self) -> String {
        "./app".to_string()
    }

    pub fn get_logger_import_path_from_src(&self) -> String {
        match self.arch {
            Architecture::Modular => "./shared/utils/logger".to_string(),
            _ => "./utils/logger".to_string(),
        }
    }

    pub fn get_logger_import_path_from_middleware(&self) -> String {
        match self.arch {
            Architecture::Modular => "../shared/utils/logger".to_string(),
            _ => "../utils/logger".to_string(),
        }
    }

    pub fn get_error_middleware_import_path_from_src(&self) -> String {
        "./middleware/error.middleware".to_string()
    }

    pub fn get_env_config_import_path_from_src(&self) -> String {
        "./config/env.config".to_string()
    }

    pub fn get_route_import_path(&self, module: &str) -> String {
        match self.arch {
            Architecture::Clean => format!("../presentation/routes/{}/{}", module, module),
            Architecture::Mvc => format!("./{}", module),
            Architecture::Modular => format!("../modules/{}/routes/{}", module, module),
            Architecture::Hexagonal => format!("../adapters/inbound/http/routes/{}", module),
            Architecture::Microservice => format!("./{}", module),
        }
    }

    pub fn get_error_middleware_import_path_from_module(&self, _module: &str) -> String {
        match self.arch {
            Architecture::Modular => "../../../middleware/error.middleware".to_string(),
            Architecture::Mvc => "../../middleware/error.middleware".to_string(),
            Architecture::Clean => "../../../../middleware/error.middleware".to_string(),
            Architecture::Hexagonal => "../../../../../../middleware/error.middleware".to_string(),
            Architecture::Microservice => "../../middleware/error.middleware".to_string(),
        }
    }

    pub fn get_logger_import_path_from_config(&self) -> String {
        match self.arch {
            Architecture::Modular => "../shared/utils/logger".to_string(),
            _ => "../utils/logger".to_string(),
        }
    }

    pub fn save_config(&self, project_path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
        let config_path = project_path.join(".acrocoder.json");
        let content = serde_json::to_string_pretty(self)?;
        std::fs::write(config_path, content)?;
        Ok(())
    }

    pub fn load_config() -> Result<Self, Box<dyn std::error::Error>> {
        let config_path = std::path::Path::new(".acrocoder.json");
        if !config_path.exists() {
            return Err("Not an Acrocoder project (.acrocoder.json not found)".into());
        }
        let content = std::fs::read_to_string(config_path)?;
        let config: Self = serde_json::from_str(&content)?;
        Ok(config)
    }
}

pub fn create_project(config: ProjectConfig) -> Result<(), Box<dyn std::error::Error>> {
    let start = std::time::Instant::now();

    printer::print_banner();
    printer::print_project_info(&config);

    let project_path = PathBuf::from(&config.name);

    if project_path.exists() {
        return Err(format!("Directory '{}' already exists.", config.name).into());
    }

    printer::step("Creating project structure...");
    std::fs::create_dir_all(&project_path)?;
    structure::create_directories(&project_path, &config)?;
    printer::done("Project structure created");

    printer::step("Generating package.json...");
    templates::package_json::generate(&project_path, &config)?;
    config.save_config(&project_path)?;
    printer::done("Package.json and config generated");

    if config.typescript {
        printer::step("Configuring TypeScript...");
        templates::tsconfig::generate(&project_path)?;
        printer::done("TypeScript configured");
    }

    printer::step("Generating source files...");
    templates::app::generate(&project_path, &config)?;
    templates::server::generate(&project_path, &config)?;
    templates::config::generate(&project_path, &config)?;
    templates::middleware::generate(&project_path, &config)?;
    templates::routes::generate(&project_path, &config)?;
    templates::utils::generate(&project_path, &config)?;
    printer::done("Source files generated");

    if config.db.is_some() {
        printer::step("Configuring database...");
        templates::database::generate(&project_path, &config)?;
        printer::done("Database configured");
    }

    if config.auth.is_some() {
        printer::step("Setting up authentication...");
        templates::auth::generate(&project_path, &config)?;
        printer::done("Authentication configured");
    }

    printer::step("Generating modules...");
    templates::modules::generate(&project_path, &config)?;
    printer::done("Modules generated");

    printer::step("Adding production configurations...");
    templates::production::generate(&project_path, &config)?;
    printer::done("Production configs added");

    printer::step("Setting up testing...");
    templates::testing::generate(&project_path, &config)?;
    printer::done("Testing configured");

    if !config.skip_install {
        printer::step("Installing dependencies...");
        install_dependencies(&project_path)?;
        printer::done("Dependencies installed");
    } else {
        printer::print_warning("Skipping dependency installation (--skip-install)");
    }

    if config.git {
        printer::step("Initializing git repository...");
        init_git(&project_path)?;
        printer::done("Git repository initialized");
    }

    let elapsed = start.elapsed();
    printer::print_success(&config.name, elapsed);

    Ok(())
}

fn install_dependencies(project_path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let npm = if cfg!(target_os = "windows") { "npm.cmd" } else { "npm" };

    let output = std::process::Command::new(npm)
        .arg("install")
        .current_dir(project_path)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("npm install failed: {}", stderr).into());
    }
    Ok(())
}

fn init_git(project_path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let _ = std::process::Command::new("git").arg("init").current_dir(project_path)
        .stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped()).output();
    let _ = std::process::Command::new("git").args(["add", "."]).current_dir(project_path)
        .stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped()).output();
    let _ = std::process::Command::new("git")
        .args(["commit", "-m", "🚀 Initial commit - Generated by Acrocoder"])
        .current_dir(project_path)
        .stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped()).output();
    Ok(())
}
