/**
 * Logger interface for consistent logging across the library
 */
export interface Logger {
  debug(message: string, ...meta: any[]): void;
  info(message: string, ...meta: any[]): void;
  warn(message: string, ...meta: any[]): void;
  error(message: string, ...meta: any[]): void;
}

/**
 * Console logger implementation
 */
export class ConsoleLogger implements Logger {
  constructor(private readonly options: { level: 'debug' | 'info' | 'warn' | 'error' } = { level: 'info' }) {}

  debug(message: string, ...meta: any[]): void {
    if (this.options.level === 'debug') {
      console.debug(`[passport-atprotocol] ${message}`, ...meta);
    }
  }

  info(message: string, ...meta: any[]): void {
    if (this.options.level === 'debug' || this.options.level === 'info') {
      console.info(`[passport-atprotocol] ${message}`, ...meta);
    }
  }

  warn(message: string, ...meta: any[]): void {
    if (this.options.level === 'debug' || this.options.level === 'info' || this.options.level === 'warn') {
      console.warn(`[passport-atprotocol] ${message}`, ...meta);
    }
  }

  error(message: string, ...meta: any[]): void {
    console.error(`[passport-atprotocol] ${message}`, ...meta);
  }
}

/**
 * Silent logger implementation
 */
export class SilentLogger implements Logger {
  debug(message: string, ...meta: any[]): void {}
  info(message: string, ...meta: any[]): void {}
  warn(message: string, ...meta: any[]): void {}
  error(message: string, ...meta: any[]): void {}
}
