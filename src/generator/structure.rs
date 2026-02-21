use crate::cli::*;
use std::path::PathBuf;

pub fn create_directories(
    project_path: &PathBuf,
    config: &super::ProjectConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    match config.arch {
        Architecture::Clean => create_clean_arch(project_path, config)?,
        Architecture::Mvc => create_mvc_arch(project_path, config)?,
        Architecture::Modular => create_modular_arch(project_path, config)?,
        Architecture::Hexagonal => create_hexagonal_arch(project_path, config)?,
        Architecture::Microservice => create_microservice_arch(project_path, config)?,
    }

    // Common directories (needed by all architectures)
    let common_dirs = vec![
        "src/config",
        "src/middleware",
        "src/utils",
        "src/types",
        "src/routes",
        "src/modules/user",
        "src/modules/health",
        "src/modules/auth",
        "tests",
        "tests/unit",
        "tests/integration",
    ];

    for dir in common_dirs {
        std::fs::create_dir_all(project_path.join(dir))?;
    }

    Ok(())
}

fn create_clean_arch(
    project_path: &PathBuf,
    _config: &super::ProjectConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let dirs = vec![
        "src/domain/entities",
        "src/domain/repositories",
        "src/domain/use-cases",
        "src/application/services",
        "src/application/dtos",
        "src/infrastructure/database",
        "src/infrastructure/repositories",
        "src/infrastructure/external",
        "src/presentation/controllers",
        "src/presentation/routes",
        "src/presentation/validators",
        "src/core/errors",
        "src/core/interfaces",
    ];

    for dir in dirs {
        std::fs::create_dir_all(project_path.join(dir))?;
    }

    Ok(())
}

fn create_mvc_arch(
    project_path: &PathBuf,
    _config: &super::ProjectConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let dirs = vec![
        "src/models",
        "src/views",
        "src/controllers",
        "src/routes",
        "src/services",
        "src/database",
    ];

    for dir in dirs {
        std::fs::create_dir_all(project_path.join(dir))?;
    }

    Ok(())
}

fn create_modular_arch(
    project_path: &PathBuf,
    _config: &super::ProjectConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let dirs = vec![
        "src/modules/user/controllers",
        "src/modules/user/services",
        "src/modules/user/models",
        "src/modules/user/routes",
        "src/modules/user/validators",
        "src/modules/user/dtos",
        "src/modules/health",
        "src/core/database",
        "src/core/errors",
        "src/core/interfaces",
        "src/shared",
    ];

    for dir in dirs {
        std::fs::create_dir_all(project_path.join(dir))?;
    }

    Ok(())
}

fn create_hexagonal_arch(
    project_path: &PathBuf,
    _config: &super::ProjectConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let dirs = vec![
        "src/domain/models",
        "src/domain/ports/inbound",
        "src/domain/ports/outbound",
        "src/domain/services",
        "src/adapters/inbound/http/controllers",
        "src/adapters/inbound/http/routes",
        "src/adapters/outbound/persistence",
        "src/adapters/outbound/external",
        "src/core/config",
    ];

    for dir in dirs {
        std::fs::create_dir_all(project_path.join(dir))?;
    }

    Ok(())
}

fn create_microservice_arch(
    project_path: &PathBuf,
    _config: &super::ProjectConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let services = vec!["api-gateway", "auth", "user"];

    for service in &services {
        let dirs = vec![
            format!("services/{}/src/config", service),
            format!("services/{}/src/controllers", service),
            format!("services/{}/src/services", service),
            format!("services/{}/src/routes", service),
            format!("services/{}/src/models", service),
            format!("services/{}/src/middleware", service),
            format!("services/{}/src/utils", service),
        ];

        for dir in dirs {
            std::fs::create_dir_all(project_path.join(dir))?;
        }
    }

    // Shared libs
    std::fs::create_dir_all(project_path.join("shared/src"))?;
    std::fs::create_dir_all(project_path.join("docker"))?;

    Ok(())
}
