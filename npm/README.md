# NodeGen CLI ⚡

> **Lightning-fast Node.js backend scaffolding CLI built in Rust.**

NodeGen allows you to generate production-ready, scalable, and secure Node.js backends in seconds. It bridges the gap between simple boilerplate and complex enterprise frameworks by providing opinionated architectural patterns and modern best practices out of the box.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Rust](https://img.shields.io/badge/built%20with-Rust-orange.svg)
![Node.js](https://img.shields.io/badge/scaffolds-Node.js-green.svg)

---

## 🚀 Speed Demo

NodeGen scaffolds a complete project with authentication, database integration, logging, validation, and Docker support in **less than 1 second**.

## ✨ Features

- **Blazing Fast**: Compiled Rust binary for near-instant execution.
- **Multiple Architectures**: Clean Architecture, MVC, Modular, Hexagonal, and Microservices.
- **Framework Support**: Express, Fastify, and NestJS.
- **Database Ready**: PostgreSQL, MongoDB, MySQL, and SQLite (Prisma, Mongoose, Sequelize, TypeORM).
- **Batteries Included Auth**: JWT, Sessions, OAuth (Google/GitHub), and Firebase.
- **Production Grade**:
  - 🛡️ **Security**: Helmet, HPP, Rate-limiting.
  - 📝 **Logging**: Winston or Pino.
  - ✅ **Validation**: Zod or Joi.
  - 🧪 **Testing**: Jest or Vitest.
  - 🐳 **DevOps**: Docker, Docker Compose, and GitHub Actions CI/CD.
  - 📖 **API Docs**: Swagger (OpenAPI 3.0) integration.

---

## 📦 Installation

### Via Cargo
```bash
cargo install nodegen-cli
```

### Via NPM
```bash
npx nodegen create my-api
```

---

## 🛠 Usage

### Create a New Project

The `create` command is the main entry point for scaffolding.

```bash
# Basic project
nodegen create my-api

# Custom project with specific stack
nodegen create my-api \
  --arch clean \
  --framework express \
  --db postgres \
  --auth jwt \
  --test vitest
```

**Options:**
- `--arch`: `clean`, `mvc`, `modular`, `hexagonal`, `microservice`
- `--framework`: `express`, `fastify`, `nest`
- `--db`: `postgres`, `mongodb`, `mysql`, `sqlite`
- `--auth`: `jwt`, `session`, `oauth`, `firebase`
- `--test`: `jest`, `vitest`
- `--validation`: `zod`, `joi`
- `--logger`: `winston`, `pino`
- `--skip-install`: Skip automatic `npm install`
- `--git`: Initialize git repository (default: true)

### Generate Modules

Generate new resources or components in an existing project.

```bash
# Generate a full CRUD module
nodegen generate module users --crud

# Generate middleware
nodegen generate middleware auth
```

### Add Features

Easily add complex configurations to an existing project.

```bash
nodegen add docker
nodegen add swagger
nodegen add cicd
nodegen add websocket
```

---

## 📂 Architecture Overview

NodeGen supports multiple patterns. For example, the **Clean Architecture** layout:

```text
src/
├── domain/            # Entities & Business Rules
├── application/       # Use Cases & Services
├── infrastructure/    # DB, Repositories, External Services
├── presentation/      # Controllers, Routes, Validators
└── core/              # Shared interfaces & global errors
```

While the **Modular** layout organizes by domain:

```text
src/
├── modules/
│   ├── auth/          # Controllers, Services, Routes for Auth
│   ├── user/          # Controllers, Services, Routes for User
│   └── health/        # Health check module
├── shared/            # Shared utils & middleware
└── core/              # Core configs
```

---

## 🛠 Built With

- [Clap](https://clap.rs/) - Command Line Argument Parser
- [Serde](https://serde.rs/) - Serialization/Deserialization
- [Colored](https://github.com/mackwic/colored) (via ANSI) - ANSI Escape Codes for UI
- [Tokio](https://tokio.rs/) (Logic-only) - Optional Async features

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

Generated with ❤️ by [Acrocoder](https://github.com/naimishverma/nodegen-cli)
