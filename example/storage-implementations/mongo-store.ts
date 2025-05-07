import { StateStore, SessionStore } from '../../src/storage';
import { MongoClient, Collection } from 'mongodb';

/**
 * MongoDB state store implementation
 */
export class MongoStateStore implements StateStore {
  private client: MongoClient;
  private collection: Collection;
  
  constructor(options: { url: string; dbName: string; collectionName?: string }) {
    this.client = new MongoClient(options.url);
    const db = this.client.db(options.dbName);
    this.collection = db.collection(options.collectionName || 'atproto_states');
    this.connect();
  }
  
  private async connect() {
    await this.client.connect();
    await this.collection.createIndex({ createdAt: 1 }, { expireAfterSeconds: 3600 });
  }
  
  async set(key: string, internalState: any): Promise<void> {
    await this.collection.updateOne(
      { _id: key },
      { 
        $set: { 
          ...internalState,
          createdAt: new Date() 
        } 
      },
      { upsert: true }
    );
  }
  
  async get(key: string): Promise<any | undefined> {
    const result = await this.collection.findOne({ _id: key });
    if (!result) return undefined;
    
    const { _id, createdAt, ...state } = result;
    return state;
  }
  
  async del(key: string): Promise<void> {
    await this.collection.deleteOne({ _id: key });
  }
  
  async close(): Promise<void> {
    await this.client.close();
  }
}

/**
 * MongoDB session store implementation
 */
export class MongoSessionStore implements SessionStore {
  private client: MongoClient;
  private collection: Collection;
  
  constructor(options: { url: string; dbName: string; collectionName?: string }) {
    this.client = new MongoClient(options.url);
    const db = this.client.db(options.dbName);
    this.collection = db.collection(options.collectionName || 'atproto_sessions');
    this.connect();
  }
  
  private async connect() {
    await this.client.connect();
    await this.collection.createIndex({ updatedAt: 1 }, { expireAfterSeconds: 86400 * 30 });
  }
  
  async set(sub: string, sessionData: any): Promise<void> {
    await this.collection.updateOne(
      { _id: sub },
      { 
        $set: { 
          ...sessionData,
          updatedAt: new Date() 
        } 
      },
      { upsert: true }
    );
  }
  
  async get(sub: string): Promise<any | undefined> {
    const result = await this.collection.findOne({ _id: sub });
    if (!result) return undefined;
    
    const { _id, updatedAt, ...sessionData } = result;
    return sessionData;
  }
  
  async del(sub: string): Promise<void> {
    await this.collection.deleteOne({ _id: sub });
  }
  
  async close(): Promise<void> {
    await this.client.close();
  }
}
