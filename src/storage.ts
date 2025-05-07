/**
 * Interface for state storage implementations
 */
export interface StateStore {
  set(key: string, internalState: any): Promise<void>;
  get(key: string): Promise<any | undefined>;
  del(key: string): Promise<void>;
}

/**
 * Interface for session storage implementations
 */
export interface SessionStore {
  set(sub: string, sessionData: any): Promise<void>;
  get(sub: string): Promise<any | undefined>;
  del(sub: string): Promise<void>;
}

/**
 * In-memory state store implementation (for development only)
 */
export class InMemoryStateStore implements StateStore {
  private store = new Map<string, any>();

  async set(key: string, internalState: any): Promise<void> {
    this.store.set(key, internalState);
  }

  async get(key: string): Promise<any | undefined> {
    return this.store.get(key);
  }

  async del(key: string): Promise<void> {
    this.store.delete(key);
  }
}

/**
 * In-memory session store implementation (for development only)
 */
export class InMemorySessionStore implements SessionStore {
  private store = new Map<string, any>();

  async set(sub: string, sessionData: any): Promise<void> {
    this.store.set(sub, sessionData);
  }

  async get(sub: string): Promise<any | undefined> {
    return this.store.get(sub);
  }

  async del(sub: string): Promise<void> {
    this.store.delete(sub);
  }
}
