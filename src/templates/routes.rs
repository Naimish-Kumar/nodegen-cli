use crate::cli::*;
use crate::generator::ProjectConfig;
use std::path::PathBuf;

pub fn generate(
    project_path: &PathBuf,
    config: &ProjectConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let ext = config.get_ext();
    let user_route_import = config.get_route_import_path("user");
    let health_route_import = config.get_route_import_path("health");

    let content = format!(
        r#"import {{ Router }} from 'express';
import userRoutes from '{user_route_import}.routes';
import healthRoutes from '{health_route_import}.routes';

export const apiRoutes = Router();

apiRoutes.use('/users', userRoutes);
apiRoutes.use('/health', healthRoutes);
"#,
        user_route_import = user_route_import,
        health_route_import = health_route_import
    );

    std::fs::write(
        project_path.join(format!("src/routes/index.{}", ext)),
        content,
    )?;

    Ok(())
}
