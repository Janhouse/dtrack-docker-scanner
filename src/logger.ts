type LogLevel = "debug" | "info" | "warn" | "error";

const LOG_COLORS = {
  debug: "\x1b[90m", // Gray
  info: "\x1b[0m", // Default
  warn: "\x1b[33m", // Yellow
  error: "\x1b[31m", // Red
  reset: "\x1b[0m",
} as const;

const LOG_SYMBOLS = {
  success: "\u2713",
  error: "\u2717",
  warning: "\u26A0",
  info: "\u2022",
} as const;

class Logger {
  private formatTimestamp(): string {
    return new Date().toISOString().replace("T", " ").substring(0, 19);
  }

  private log(level: LogLevel, message: string, ...args: unknown[]): void {
    const timestamp = this.formatTimestamp();
    const color = LOG_COLORS[level];
    const reset = LOG_COLORS.reset;
    const prefix = `[${timestamp}]`;

    const formattedMessage =
      args.length > 0 ? `${message} ${args.map(String).join(" ")}` : message;

    console.log(`${color}${prefix} ${formattedMessage}${reset}`);
  }

  debug(message: string, ...args: unknown[]): void {
    this.log("debug", message, ...args);
  }

  info(message: string, ...args: unknown[]): void {
    this.log("info", message, ...args);
  }

  warn(message: string, ...args: unknown[]): void {
    this.log("warn", `${LOG_SYMBOLS.warning} ${message}`, ...args);
  }

  error(message: string, ...args: unknown[]): void {
    this.log("error", `${LOG_SYMBOLS.error} ${message}`, ...args);
  }

  success(message: string, ...args: unknown[]): void {
    this.log("info", `${LOG_SYMBOLS.success} ${message}`, ...args);
  }

  section(title: string): void {
    this.info(`=== ${title} ===`);
  }

  indent(message: string, ...args: unknown[]): void {
    this.info(`  ${message}`, ...args);
  }

  indentSuccess(message: string, ...args: unknown[]): void {
    this.info(`  ${LOG_SYMBOLS.success} ${message}`, ...args);
  }

  indentError(message: string, ...args: unknown[]): void {
    this.info(`  ${LOG_SYMBOLS.error} ${message}`, ...args);
  }
}

export const logger = new Logger();
