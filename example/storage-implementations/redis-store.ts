import { StateStore, SessionStore } from '../../src/storage';
import { createClient } from 'redis';

/**
 * Redis state store implementation
 */
export class RedisStateStore implements StateStore {
  private client;
  private prefix: string;
  
  constructor(options: { url: string; prefix?: string }) {
    this.client = createClient({ url: options.url });
    this.prefix = options.prefix || 'atproto:state:';
    this.client.connect();
  }
  
  async set(key: string, internalState: any): Promise<void> {
    await this.client.set(
      `${this.prefix}${key}`,
      JSON.stringify(internalState),
      { EX: 3600 } // 1 hour expiration
    );
  }
  
  async get(key: string): Promise<any | undefined> {
    const data = await this.client.get(`${this.prefix}${key}`);
    if (!data) return undefined;
    return JSON.parse(data);
  }
  
  async del(key: string): Promise<void> {
    await this.client.del(`${this.prefix}${key}`);
  }
  
  async close(): Promise<void> {
    await this.client.quit();
  }
}

/**
 * Redis session store implementation
 */
export class RedisSessionStore implements SessionStore {
  private client;
  private prefix: string;
  
  constructor(options: { url: string; prefix?: string }) {
    this.client = createClient({ url: options.url });
    this.prefix = options.prefix || 'atproto:session:';
    this.client.connect();
  }
  
  async set(sub: string, sessionData: any): Promise<void> {
    await this.client.set(
      `${this.prefix}${sub}`,
      JSON.stringify(sessionData),
      { EX: 86400 * 30 } // 30 days expiration
    );
  }
  
  async get(sub: string): Promise<any | undefined> {
    const data = await this.client.get(`${this.prefix}${sub}`);
    if (!data) return undefined;
    return JSON.parse(data);
  }
  
  async del(sub: string): Promise<void> {
    await this.client.del(`${this.prefix}${sub}`);
  }
  
  async close(): Promise<void> {
    await this.client.quit();
  }
}
