import { ConsoleLogger, SilentLogger } from '../logger';

describe('ConsoleLogger', () => {
  let originalConsole;
  let mockConsole;

  beforeEach(() => {
    originalConsole = global.console;
    mockConsole = {
      debug: jest.fn(),
      info: jest.fn(),
      warn: jest.fn(),
      error: jest.fn(),
    };
    global.console = mockConsole;
  });

  afterEach(() => {
    global.console = originalConsole;
  });

  test('debug level logs all messages', () => {
    const logger = new ConsoleLogger({ level: 'debug' });
    
    logger.debug('Debug message');
    logger.info('Info message');
    logger.warn('Warn message');
    logger.error('Error message');
    
    expect(mockConsole.debug).toHaveBeenCalledWith('[passport-atprotocol] Debug message');
    expect(mockConsole.info).toHaveBeenCalledWith('[passport-atprotocol] Info message');
    expect(mockConsole.warn).toHaveBeenCalledWith('[passport-atprotocol] Warn message');
    expect(mockConsole.error).toHaveBeenCalledWith('[passport-atprotocol] Error message');
  });

  test('info level does not log debug messages', () => {
    const logger = new ConsoleLogger({ level: 'info' });
    
    logger.debug('Debug message');
    logger.info('Info message');
    logger.warn('Warn message');
    logger.error('Error message');
    
    expect(mockConsole.debug).not.toHaveBeenCalled();
    expect(mockConsole.info).toHaveBeenCalledWith('[passport-atprotocol] Info message');
    expect(mockConsole.warn).toHaveBeenCalledWith('[passport-atprotocol] Warn message');
    expect(mockConsole.error).toHaveBeenCalledWith('[passport-atprotocol] Error message');
  });
});

describe('SilentLogger', () => {
  let originalConsole;
  let mockConsole;

  beforeEach(() => {
    originalConsole = global.console;
    mockConsole = {
      debug: jest.fn(),
      info: jest.fn(),
      warn: jest.fn(),
      error: jest.fn(),
    };
    global.console = mockConsole;
  });

  afterEach(() => {
    global.console = originalConsole;
  });

  test('does not log any messages', () => {
    const logger = new SilentLogger();
    
    logger.debug('Debug message');
    logger.info('Info message');
    logger.warn('Warn message');
    logger.error('Error message');
    
    expect(mockConsole.debug).not.toHaveBeenCalled();
    expect(mockConsole.info).not.toHaveBeenCalled();
    expect(mockConsole.warn).not.toHaveBeenCalled();
    expect(mockConsole.error).not.toHaveBeenCalled();
  });
});
