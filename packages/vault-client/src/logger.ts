/**
 * Simple logger wrapper for vault-client
 * This avoids circular dependency issues and provides a consistent interface
 */

const createLogger = () => {
  const format = (level: string, message: string, meta?: unknown): string => {
    const timestamp = new Date().toISOString();
    const metaStr = meta ? ` ${JSON.stringify(meta)}` : '';
    return `[${timestamp}] [${level}] ${message}${metaStr}`;
  };

  return {
    info: (message: string, meta?: unknown) => {
      console.log(format('INFO', message, meta));
    },
    error: (message: string, meta?: unknown) => {
      console.error(format('ERROR', message, meta));
    },
    debug: (message: string, meta?: unknown) => {
      if (process.env.NODE_ENV !== 'production') {
        console.log(format('DEBUG', message, meta));
      }
    },
    warn: (message: string, meta?: unknown) => {
      console.warn(format('WARN', message, meta));
    },
  };
};

export const log = createLogger();
