use std::time::Duration;

// ANSI color helpers
const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const CYAN: &str = "\x1b[36m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const RED: &str = "\x1b[31m";
const BRIGHT_WHITE: &str = "\x1b[97m";
const BRIGHT_CYAN: &str = "\x1b[96m";
const BRIGHT_GREEN: &str = "\x1b[92m";
const BRIGHT_YELLOW: &str = "\x1b[93m";
const BRIGHT_RED: &str = "\x1b[91m";
const BRIGHT_MAGENTA: &str = "\x1b[95m";
const BRIGHT_BLUE: &str = "\x1b[94m";

pub fn print_banner() {
    println!(
        "{BOLD}{CYAN}\
    \n    ╔═══════════════════════════════════════════════════════════╗\
    \n    ║                                                           ║\
    \n    ║   ▄▀█ █▀▀ █▀█ █▀█ █▀▀ █▀█ █▀▄ █▀▀ █▀█                     ║\
    \n    ║   █▀█ █▄▄ █▀▄ █▄█ █▄▄ █▄█ █▄▀ ██▄ █▀▄                     ║\
    \n    ║                                                           ║\
    \n    ║          ⚡ Acrocoder Backend Generator v0.0.3 ⚡           ║\
    \n    ║                                                           ║\
    \n    ╚═══════════════════════════════════════════════════════════╝\
    \n{RESET}"
    );
}

pub fn print_project_info(config: &crate::generator::ProjectConfig) {
    println!();
    println!("  {BOLD}{BRIGHT_WHITE}Project:{RESET}      {BRIGHT_CYAN}{}{RESET}", config.name);
    println!("  {BOLD}{BRIGHT_WHITE}Architecture:{RESET} {BRIGHT_YELLOW}{}{RESET}", config.arch);
    println!("  {BOLD}{BRIGHT_WHITE}Framework:{RESET}    {BRIGHT_GREEN}{}{RESET}", config.framework);
    if let Some(db) = &config.db {
        println!("  {BOLD}{BRIGHT_WHITE}Database:{RESET}     {BRIGHT_MAGENTA}{}{RESET}", db);
        if let Some(orm) = config.resolve_orm() {
            println!("  {BOLD}{BRIGHT_WHITE}ORM:{RESET}          {BRIGHT_MAGENTA}{}{RESET}", orm);
        }
    }
    if let Some(auth) = &config.auth {
        println!("  {BOLD}{BRIGHT_WHITE}Auth:{RESET}         {BRIGHT_RED}{}{RESET}", auth);
    }
    println!("  {BOLD}{BRIGHT_WHITE}Testing:{RESET}      {BRIGHT_BLUE}{}{RESET}", config.test);
    println!("  {BOLD}{BRIGHT_WHITE}Validation:{RESET}   {BRIGHT_BLUE}{}{RESET}", config.validation);
    println!("  {BOLD}{BRIGHT_WHITE}Logger:{RESET}       {BRIGHT_BLUE}{}{RESET}", config.logger);
    println!();
    println!("  {DIM}{}{RESET}", "─".repeat(50));
    println!();
}

pub fn step(msg: &str) {
    print!("  {CYAN}⠋{RESET} {msg}");
    use std::io::Write;
    std::io::stdout().flush().ok();
}

pub fn done(msg: &str) {
    println!("\r  {BOLD}{GREEN}✔{RESET} {BRIGHT_WHITE}{msg}{RESET}");
}

pub fn print_success(project_name: &str, elapsed: Duration) {
    println!();
    println!("  {DIM}{}{RESET}", "─".repeat(50));
    println!();
    println!("  {BOLD}{GREEN}✔{RESET} Project '{BOLD}{BRIGHT_CYAN}{project_name}{RESET}' created successfully! 🚀");
    println!("  {BOLD}{GREEN}✔{RESET} Done in {:.1} seconds ⚡", elapsed.as_secs_f64());
    println!();
    println!("  {BOLD}{BRIGHT_WHITE}Next steps:{RESET}");
    println!("    {CYAN}→{RESET} {YELLOW}cd {project_name}{RESET}");
    println!("    {CYAN}→{RESET} {YELLOW}cp .env.example .env{RESET}");
    println!("    {CYAN}→{RESET} {YELLOW}npm run dev{RESET}");
    println!();
    println!("  📖  {DIM}Read the README.md for full documentation{RESET}");
    println!();
}

pub fn print_error(msg: &str) {
    eprintln!("  {BOLD}{RED}✖{RESET} {BRIGHT_RED}{msg}{RESET}");
}

pub fn print_warning(msg: &str) {
    println!("  {BOLD}{YELLOW}⚠{RESET} {BRIGHT_YELLOW}{msg}{RESET}");
}

pub fn print_info(msg: &str) {
    println!("  {GREEN}{msg}{RESET}");
}
