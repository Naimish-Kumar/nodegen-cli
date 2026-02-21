use crate::generator::ProjectConfig;
use std::path::PathBuf;

pub fn generate(
    project_path: &PathBuf,
    config: &ProjectConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    generate_health_module(project_path, config)?;
    generate_user_module(project_path, config)?;
    Ok(())
}

fn generate_health_module(
    project_path: &PathBuf,
    config: &ProjectConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let ext = config.get_ext();
    let route_dir = config.get_route_path("health");
    
    std::fs::create_dir_all(project_path.join(&route_dir))?;

    let route_content = r#"import { Router } from 'express';

const router = Router();

router.get('/', (_req, res) => {
  res.json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
  });
});

export default router;
"#;

    std::fs::write(
        project_path.join(format!("{}/health.routes.{}", route_dir, ext)),
        route_content,
    )?;

    Ok(())
}

fn generate_user_module(
    project_path: &PathBuf,
    config: &ProjectConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let ext = config.get_ext();
    let controller_dir = config.get_controller_path("user");
    let service_dir = config.get_service_path("user");
    let route_dir = config.get_route_path("user");

    std::fs::create_dir_all(project_path.join(&controller_dir))?;
    std::fs::create_dir_all(project_path.join(&service_dir))?;
    std::fs::create_dir_all(project_path.join(&route_dir))?;

    let service_import = config.get_service_import_path("user");
    let utils_import = config.get_utils_import_path("user");

    // User Controller
    let controller = format!(
        r#"import {{ Request, Response, NextFunction }} from 'express';
import {{ UserService }} from '{service_import}.service';
import {{ ApiResponse }} from '{utils_import}';

const userService = new UserService();

export class UserController {{
  async getAll(req: Request, res: Response, next: NextFunction): Promise<void> {{
    try {{
      const users = await userService.findAll();
      ApiResponse.success(res, users);
    }} catch (error) {{
      next(error);
    }}
  }}

  async getById(req: Request, res: Response, next: NextFunction): Promise<void> {{
    try {{
      const user = await userService.findById(req.params.id);
      ApiResponse.success(res, user);
    }} catch (error) {{
      next(error);
    }}
  }}

  async create(req: Request, res: Response, next: NextFunction): Promise<void> {{
    try {{
      const user = await userService.create(req.body);
      ApiResponse.created(res, user);
    }} catch (error) {{
      next(error);
    }}
  }}
}}
"#,
        service_import = service_import,
        utils_import = utils_import
    );

    // User Service
    let service = r#"export class UserService {
  async findAll(): Promise<any[]> {
    return [
      { id: '1', name: 'John Doe', email: 'john@example.com' },
      { id: '2', name: 'Jane Doe', email: 'jane@example.com' },
    ];
  }

  async findById(id: string): Promise<any> {
    return { id, name: 'John Doe', email: 'john@example.com' };
  }

  async create(data: any): Promise<any> {
    return { id: Date.now().toString(), ...data };
  }
}
"#;

    // User Routes
    let routes = r#"import { Router } from 'express';
import { UserController } from '../controllers/user.controller';

const router = Router();
const userController = new UserController();

router.get('/', (req, res, next) => userController.getAll(req, res, next));
router.get('/:id', (req, res, next) => userController.getById(req, res, next));
router.post('/', (req, res, next) => userController.create(req, res, next));

export default router;
"#;

    std::fs::write(
        project_path.join(format!("{}/user.controller.{}", controller_dir, ext)),
        controller,
    )?;
    std::fs::write(
        project_path.join(format!("{}/user.service.{}", service_dir, ext)),
        service,
    )?;
    std::fs::write(
        project_path.join(format!("{}/user.routes.{}", route_dir, ext)),
        routes,
    )?;

    Ok(())
}
