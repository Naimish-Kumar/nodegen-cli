use std::path::PathBuf;

pub fn generate(project_path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let tsconfig = r#"{
  "compilerOptions": {
    "target": "ES2022",
    "module": "commonjs",
    "lib": ["ES2022"],
    "outDir": "./dist",
    "rootDir": "./src",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "resolveJsonModule": true,
    "declaration": true,
    "declarationMap": true,
    "sourceMap": true,
    "moduleResolution": "node",
    "emitDecoratorMetadata": true,
    "experimentalDecorators": true,
    "baseUrl": ".",
    "paths": {
      "@config/*": ["src/config/*"],
      "@middleware/*": ["src/middleware/*"],
      "@modules/*": ["src/modules/*"],
      "@utils/*": ["src/utils/*"],
      "@core/*": ["src/core/*"],
      "@types/*": ["src/types/*"]
    }
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules", "dist", "tests"]
}
"#;

    std::fs::write(project_path.join("tsconfig.json"), tsconfig)?;
    Ok(())
}
