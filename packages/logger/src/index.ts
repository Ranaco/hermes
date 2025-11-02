import winston from 'winston';
import chalk from 'chalk';

// Define log levels with colors
const logLevels = {
  levels: {
    error: 0,
    warn: 1,
    info: 2,
    http: 3,
    debug: 4,
  },
  colors: {
    error: 'red',
    warn: 'yellow',
    info: 'green',
    http: 'magenta',
    debug: 'blue',
  },
};

winston.addColors(logLevels.colors);

// Custom format for development
const devFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.errors({ stack: true }),
  winston.format.printf((info: winston.Logform.TransformableInfo) => {
    const { timestamp, level, message, stack, ...meta } = info;
    const levelColor = logLevels.colors[level as keyof typeof logLevels.colors] || 'white';
    const coloredLevel = chalk[levelColor as 'red' | 'yellow' | 'green' | 'magenta' | 'blue'](level.toUpperCase().padEnd(5));
    const coloredTimestamp = chalk.gray(timestamp as string);
    
    let logMessage = `${coloredTimestamp} [${coloredLevel}] ${message}`;
    
    if (Object.keys(meta).length > 0) {
      logMessage += `\n${chalk.gray(JSON.stringify(meta, null, 2))}`;
    }
    
    if (stack) {
      logMessage += `\n${chalk.red(stack as string)}`;
    }
    
    return logMessage;
  })
);

// Production format (JSON for log aggregation)
const prodFormat = winston.format.combine(
  winston.format.timestamp(),
  winston.format.errors({ stack: true }),
  winston.format.json()
);

// Create the logger instance
const logger = winston.createLogger({
  levels: logLevels.levels,
  level: process.env.LOG_LEVEL || (process.env.NODE_ENV === 'production' ? 'info' : 'debug'),
  format: process.env.NODE_ENV === 'production' ? prodFormat : devFormat,
  transports: [
    new winston.transports.Console({
      stderrLevels: ['error'],
    }),
  ],
  // Don't exit on handled exceptions
  exitOnError: false,
});

// Add file transports in production
if (process.env.NODE_ENV === 'production') {
  logger.add(
    new winston.transports.File({
      filename: 'logs/error.log',
      level: 'error',
      maxsize: 5242880, // 5MB
      maxFiles: 5,
    })
  );
  logger.add(
    new winston.transports.File({
      filename: 'logs/combined.log',
      maxsize: 5242880, // 5MB
      maxFiles: 5,
    })
  );
}

// Stream for Morgan HTTP logger
export const httpLogStream = {
  write: (message: string) => {
    logger.http(message.trim());
  },
};

// Export typed logging functions
export const log = {
  error: (message: string, meta?: unknown) => logger.error(message, meta as object),
  warn: (message: string, meta?: unknown) => logger.warn(message, meta as object),
  info: (message: string, meta?: unknown) => logger.info(message, meta as object),
  http: (message: string, meta?: unknown) => logger.http(message, meta as object),
  debug: (message: string, meta?: unknown) => logger.debug(message, meta as object),
};

// Export the logger instance for advanced usage
export default logger;
