use crate::cli::*;
use std::path::PathBuf;

pub fn handle_generate(target: GenerateTarget) -> Result<(), Box<dyn std::error::Error>> {
    match target {
        GenerateTarget::Module { name, crud } => generate_module(&name, crud)?,
        GenerateTarget::Resource { name } => generate_module(&name, true)?,
        GenerateTarget::Middleware { name } => generate_middleware(&name)?,
    }
    Ok(())
}

pub fn handle_add(feature: AddFeature) -> Result<(), Box<dyn std::error::Error>> {
    match feature {
        AddFeature::Docker => add_docker()?,
        AddFeature::Swagger => add_swagger()?,
        AddFeature::Cicd => add_cicd()?,
        AddFeature::Websocket => add_websocket()?,
        AddFeature::Ratelimit => add_ratelimit()?,
        AddFeature::Testing { framework } => add_testing(framework)?,
    }
    Ok(())
}

fn to_pascal_case(s: &str) -> String {
    s.split(|c: char| c == '_' || c == '-')
        .map(|w| { let mut c = w.chars(); match c.next() { None => String::new(), Some(f) => f.to_uppercase().collect::<String>() + c.as_str() } })
        .collect()
}

fn generate_module(name: &str, crud: bool) -> Result<(), Box<dyn std::error::Error>> {
    let config = super::ProjectConfig::load_config()?;
    let ext = if config.typescript { "ts" } else { "js" };
    let pascal = to_pascal_case(name);

    let controller_dir = config.get_controller_path(name);
    let service_dir = config.get_service_path(name);
    let route_dir = config.get_route_path(name);

    std::fs::create_dir_all(&controller_dir)?;
    std::fs::create_dir_all(&service_dir)?;
    std::fs::create_dir_all(&route_dir)?;

    let service_import = config.get_service_import_path(name);

    let controller = format!(r#"import {{ Request, Response, NextFunction }} from 'express';
import {{ {pascal}Service }} from '{service_import}.service';

const service = new {pascal}Service();

export class {pascal}Controller {{
  async getAll(req: Request, res: Response, next: NextFunction): Promise<void> {{
    try {{ const items = await service.findAll(); res.json({{ success: true, data: items }}); }} catch (e) {{ next(e); }}
  }}
  async getById(req: Request, res: Response, next: NextFunction): Promise<void> {{
    try {{ const item = await service.findById(req.params.id); res.json({{ success: true, data: item }}); }} catch (e) {{ next(e); }}
  }}{crud_methods}
}}
"#, pascal = pascal, service_import = service_import,
    crud_methods = if crud { format!(r#"
  async create(req: Request, res: Response, next: NextFunction): Promise<void> {{
    try {{ const item = await service.create(req.body); res.status(201).json({{ success: true, data: item }}); }} catch (e) {{ next(e); }}
  }}
  async update(req: Request, res: Response, next: NextFunction): Promise<void> {{
    try {{ const item = await service.update(req.params.id, req.body); res.json({{ success: true, data: item }}); }} catch (e) {{ next(e); }}
  }}
  async delete(req: Request, res: Response, next: NextFunction): Promise<void> {{
    try {{ await service.delete(req.params.id); res.status(204).send(); }} catch (e) {{ next(e); }}
  }}"#) } else { String::new() });

    let service_content = format!(r#"export class {pascal}Service {{
  async findAll(): Promise<any[]> {{ return []; }}
  async findById(id: string): Promise<any | null> {{ return null; }}
  async create(data: any): Promise<any> {{ return data; }}
  async update(id: string, data: any): Promise<any> {{ return data; }}
  async delete(id: string): Promise<void> {{}}
}}
"#, pascal = pascal);

    let routes_content = format!(r#"import {{ Router }} from 'express';
import {{ {pascal}Controller }} from '../controllers/{name}.controller';
const router = Router();
const ctrl = new {pascal}Controller();
router.get('/', (req, res, next) => ctrl.getAll(req, res, next));
router.get('/:id', (req, res, next) => ctrl.getById(req, res, next));
router.post('/', (req, res, next) => ctrl.create(req, res, next));
router.put('/:id', (req, res, next) => ctrl.update(req, res, next));
router.delete('/:id', (req, res, next) => ctrl.delete(req, res, next));
export default router;
"#, name = name, pascal = pascal);

    std::fs::write(format!("{}/{}.controller.{}", controller_dir, name, ext), controller)?;
    std::fs::write(format!("{}/{}.service.{}", service_dir, name, ext), service_content)?;
    std::fs::write(format!("{}/{}.routes.{}", route_dir, name, ext), routes_content)?;

    crate::utils::printer::print_info(&format!("✔ Module '{}' generated successfully (Architecture: {})", name, config.arch));
    Ok(())
}

fn generate_middleware(name: &str) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::create_dir_all("src/middleware")?;
    let content = format!("import {{ Request, Response, NextFunction }} from 'express';\n\nexport const {name}Middleware = (req: Request, res: Response, next: NextFunction): void => {{\n  // TODO: Implement {name} middleware\n  next();\n}};\n", name = name);
    std::fs::write(format!("src/middleware/{}.middleware.ts", name), content)?;
    crate::utils::printer::print_info(&format!("✔ Middleware '{}' generated", name));
    Ok(())
}

fn add_docker() -> Result<(), Box<dyn std::error::Error>> {
    std::fs::write("Dockerfile", "FROM node:20-alpine AS builder\nWORKDIR /app\nCOPY package*.json ./\nRUN npm ci --only=production\nCOPY . .\nRUN npm run build\n\nFROM node:20-alpine\nWORKDIR /app\nCOPY --from=builder /app/dist ./dist\nCOPY --from=builder /app/node_modules ./node_modules\nCOPY --from=builder /app/package.json ./\nEXPOSE 3000\nENV NODE_ENV=production\nCMD [\"node\", \"dist/server.js\"]\n")?;
    std::fs::write(".dockerignore", "node_modules\ndist\n.env\n*.log\n.git\ncoverage\ntests\n")?;
    std::fs::write("docker-compose.yml", "version: '3.8'\nservices:\n  app:\n    build: .\n    ports:\n      - '3000:3000'\n    env_file: .env\n    restart: unless-stopped\n")?;
    crate::utils::printer::print_info("✔ Docker configuration added");
    Ok(())
}

fn add_swagger() -> Result<(), Box<dyn std::error::Error>> {
    std::fs::create_dir_all("src/config")?;
    std::fs::write("src/config/swagger.config.ts", "import swaggerJSDoc from 'swagger-jsdoc';\n\nexport const swaggerSpec = swaggerJSDoc({\n  swaggerDefinition: {\n    openapi: '3.0.0',\n    info: { title: 'API', version: '1.0.0' },\n    servers: [{ url: 'http://localhost:3000' }],\n  },\n  apis: ['./src/**/*.ts'],\n});\n")?;
    crate::utils::printer::print_info("✔ Swagger configuration added");
    Ok(())
}

fn add_cicd() -> Result<(), Box<dyn std::error::Error>> {
    std::fs::create_dir_all(".github/workflows")?;
    std::fs::write(".github/workflows/ci.yml", "name: CI\non:\n  push:\n    branches: [main]\n  pull_request:\n    branches: [main]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: actions/setup-node@v4\n        with:\n          node-version: 20.x\n          cache: npm\n      - run: npm ci\n      - run: npm run lint\n      - run: npm run build\n      - run: npm test\n")?;
    crate::utils::printer::print_info("✔ CI/CD pipeline added");
    Ok(())
}

fn add_websocket() -> Result<(), Box<dyn std::error::Error>> {
    std::fs::create_dir_all("src/websocket")?;
    std::fs::write("src/websocket/index.ts", "import { Server as HttpServer } from 'http';\nimport { Server, Socket } from 'socket.io';\nimport { logger } from '../utils/logger';\n\nexport class WebSocketServer {\n  private io: Server;\n  constructor(httpServer: HttpServer) {\n    this.io = new Server(httpServer, { cors: { origin: '*' } });\n    this.io.on('connection', (socket: Socket) => {\n      logger.info(`Client connected: ${socket.id}`);\n      socket.on('disconnect', () => logger.info(`Disconnected: ${socket.id}`));\n    });\n  }\n}\n")?;
    crate::utils::printer::print_info("✔ WebSocket support added");
    Ok(())
}

fn add_ratelimit() -> Result<(), Box<dyn std::error::Error>> {
    std::fs::create_dir_all("src/middleware")?;
    std::fs::write("src/middleware/rateLimit.middleware.ts", "import rateLimit from 'express-rate-limit';\n\nexport const rateLimiter = rateLimit({\n  windowMs: 15 * 60 * 1000,\n  max: 100,\n  message: { success: false, message: 'Too many requests' },\n  standardHeaders: true,\n  legacyHeaders: false,\n});\n")?;
    crate::utils::printer::print_info("✔ Rate limiting added");
    Ok(())
}

fn add_testing(framework: TestFramework) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::create_dir_all("tests/unit")?;
    std::fs::create_dir_all("tests/integration")?;
    match framework {
        TestFramework::Jest => std::fs::write("jest.config.js", "module.exports = {\n  preset: 'ts-jest',\n  testEnvironment: 'node',\n  roots: ['<rootDir>/tests'],\n  testMatch: ['**/*.test.ts'],\n};\n")?,
        TestFramework::Vitest => std::fs::write("vitest.config.ts", "import { defineConfig } from 'vitest/config';\nexport default defineConfig({ test: { globals: true, environment: 'node' } });\n")?,
    }
    std::fs::write("tests/unit/health.test.ts", "describe('Health', () => { it('works', () => { expect(true).toBe(true); }); });\n")?;
    crate::utils::printer::print_info(&format!("✔ Testing setup added ({})", framework));
    Ok(())
}
