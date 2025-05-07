import { InMemoryStateStore, InMemorySessionStore } from '../storage';

describe('InMemoryStateStore', () => {
  let store: InMemoryStateStore;

  beforeEach(() => {
    store = new InMemoryStateStore();
  });

  test('set and get state', async () => {
    const testState = { foo: 'bar' };
    await store.set('test-key', testState);
    const result = await store.get('test-key');
    expect(result).toEqual(testState);
  });

  test('delete state', async () => {
    const testState = { foo: 'bar' };
    await store.set('test-key', testState);
    await store.del('test-key');
    const result = await store.get('test-key');
    expect(result).toBeUndefined();
  });
});

describe('InMemorySessionStore', () => {
  let store: InMemorySessionStore;

  beforeEach(() => {
    store = new InMemorySessionStore();
  });

  test('set and get session', async () => {
    const testSession = { 
      tokenSet: { 
        access_token: 'test-token',
        refresh_token: 'test-refresh',
        expires_at: '2099-01-01'
      } 
    };
    await store.set('test-sub', testSession);
    const result = await store.get('test-sub');
    expect(result).toEqual(testSession);
  });

  test('delete session', async () => {
    const testSession = { 
      tokenSet: { 
        access_token: 'test-token',
        refresh_token: 'test-refresh',
        expires_at: '2099-01-01'
      } 
    };
    await store.set('test-sub', testSession);
    await store.del('test-sub');
    const result = await store.get('test-sub');
    expect(result).toBeUndefined();
  });
});
