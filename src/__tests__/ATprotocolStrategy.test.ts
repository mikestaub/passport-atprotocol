import { Agent } from '@atproto/api';
import { OAuthCallbackError, ClientMetadata, NodeOAuthClient } from '@atproto/oauth-client-node';
import { JoseKey } from '@atproto/jwk-jose';

import {
  ATprotocolStrategy,
  createOAuthClient,
  createATProtocolLoginMiddleware,
} from '../strategy';

import { ExpressRequestWithSession } from '../types';

jest.mock('@atproto/oauth-client-node');
jest.mock('@atproto/api', () => ({
  Agent: jest.fn().mockImplementation(() => ({
    getProfile: jest.fn(),
  })),
}));

const clientMetadata: ClientMetadata = {
  client_id:
    'https://b6f0-2601-18f-27f-b590-2c31-b649-112a-116d.ngrok-free.app/static/client-metadata.json',
  client_name: 'My Passport atproto OAuth App',
  client_uri: 'https://b6f0-2601-18f-27f-b590-2c31-b649-112a-116d.ngrok-free.app',
  redirect_uris: [
    'https://b6f0-2601-18f-27f-b590-2c31-b649-112a-116d.ngrok-free.app/auth/atprotocol/callback',
  ],
  logo_uri: 'https://b6f0-2601-18f-27f-b590-2c31-b649-112a-116d.ngrok-free.app/logo.png',
  tos_uri: 'https://b6f0-2601-18f-27f-b590-2c31-b649-112a-116d.ngrok-free.app/tos',
  policy_uri: 'https://b6f0-2601-18f-27f-b590-2c31-b649-112a-116d.ngrok-free.app/policy',
  jwks_uri:
    'https://b6f0-2601-18f-27f-b590-2c31-b649-112a-116d.ngrok-free.app/auth/atprotocol/jwks.json',
  grant_types: ['authorization_code', 'refresh_token'],
  response_types: ['code'],
  scope: 'atproto transition:generic',
  token_endpoint_auth_method: 'private_key_jwt',
  token_endpoint_auth_signing_alg: 'ES256',
  application_type: 'web',
  dpop_bound_access_tokens: true,
};

describe('ATprotocolStrategy', () => {
  let strategy;
  let mockVerify;
  let mockOAuthClient;
  let mockAgent;
  let mockProfile;
  let mockOptions;

  beforeEach(() => {
    mockProfile = {
      did: 'did:example:123',
      handle: 'test@example.com',
      displayName: 'Test User',
    };

    mockVerify = jest.fn();

    mockAgent = {
      getProfile: jest.fn().mockResolvedValue({ data: mockProfile }),
    } as any;

    mockOptions = {
      clientMetadata,
      keyset: [
        new JoseKey({
          kty: 'EC',
          crv: 'P-256',
          x: 'MKBCTNIcKUSDii11ySs3526iDZ8AiTojGyds7wY7U4Q',
          y: '4QgIARuCAiEA2lWHA3i49r5F2Q+UYK8z4zMj6C3FRIbS+X8=',
          alg: 'ES256',
          kid: '1234567890',
          d: 'dsb',
          use: 'sig',
        }),
        new JoseKey({
          kty: 'EC',
          crv: 'P-256',
          x: 'MKBCTNIcKUSDii11ySs3526iDZ8AiTojGyds7wY7U4Q',
          y: '4QgIARuCAiEA2lWHA3i49r5F2Q+UYK8z4zMj6C3FRIbS+X8=',
          alg: 'ES256',
          d: 'dsa',
          kid: '1234367890',
          use: 'sig',
        }),
        new JoseKey({
          kty: 'EC',
          d: 'dsd',
          crv: 'P-256',
          x: 'MKBCTNIcKUSDii11ySs3526iDZ8AiTojGyds7wY7U4Q',
          y: '4QgIARuCAiEA2lWHA3i49r5F2Q+UYK8z4zMj6C3FRIbS+X8=',
          alg: 'ES256',
          kid: '1234267890',
          use: 'sig',
        }),
      ],
    };

    (Agent as jest.MockedClass<typeof Agent>).mockImplementation(() => mockAgent);
    mockOAuthClient = createOAuthClient(mockOptions);
    const options = {
      oauthClient: mockOAuthClient,
      passReqToCallback: true,
    };
    strategy = new ATprotocolStrategy(options, mockVerify);
    strategy.fail = jest.fn();
    strategy.success = jest.fn();
    strategy.error = jest.fn();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('createOAuthClient', () => {
    beforeEach(() => {
      jest.clearAllMocks();
    });

    test('creates NodeOAuthClient with correct options', () => {
      createOAuthClient(mockOptions);
      expect(NodeOAuthClient).toHaveBeenCalledWith(
        expect.objectContaining({
          clientMetadata: mockOptions.clientMetadata,
          keyset: mockOptions.keyset,
          requestLock: null,
        }),
      );
    });

    test('stateStore.set stores state correctly', async () => {
      createOAuthClient(mockOptions);
      const mockNodeOAuthClient = NodeOAuthClient as jest.MockedClass<typeof NodeOAuthClient>;
      const options = mockNodeOAuthClient.mock.calls[0][0];

      await options.stateStore.set('testKey', {
        dpopJwk: { kty: 'EC', crv: 'P-256' },
        iss: 'https://example.com',
      });
      expect(options.stateStore.get('testKey')).resolves.toEqual({
        dpopJwk: { kty: 'EC', crv: 'P-256' },
        iss: 'https://example.com',
      });
    });

    test('stateStore.del removes state correctly', async () => {
      createOAuthClient(mockOptions);
      const mockNodeOAuthClient = NodeOAuthClient as jest.MockedClass<typeof NodeOAuthClient>;
      const options = mockNodeOAuthClient.mock.calls[0][0];

      await options.stateStore.set('testKey', {
        dpopJwk: { kty: 'EC', crv: 'P-256' },
        iss: 'https://example.com',
      });
      await options.stateStore.del('testKey');
      expect(options.stateStore.get('testKey')).resolves.toBeUndefined();
    });

    test('sessionStore.set stores session correctly', async () => {
      createOAuthClient(mockOptions);
      const client = createOAuthClient(mockOptions);
      const mockNodeOAuthClient = NodeOAuthClient as jest.MockedClass<typeof NodeOAuthClient>;
      const options = mockNodeOAuthClient.mock.calls[0][0];

      await options.sessionStore.set('testSub', {
        dpopJwk: { kty: 'EC', crv: 'P-256' },
        tokenSet: {
          iss: 'https://example.com',
          sub: 'testSub',
          aud: 'client123',
          scope: 'read write',
          access_token: 'test-access-token',
          token_type: 'Bearer',
        },
      });

      expect(options.sessionStore.get('testSub')).resolves.toEqual({
        dpopJwk: { kty: 'EC', crv: 'P-256' },
        tokenSet: {
          iss: 'https://example.com',
          sub: 'testSub',
          aud: 'client123',
          scope: 'read write',
          access_token: 'test-access-token',
          token_type: 'Bearer',
        },
      });
    });

    test('sessionStore.del removes session correctly', async () => {
      createOAuthClient(mockOptions);
      const mockNodeOAuthClient = NodeOAuthClient as jest.MockedClass<typeof NodeOAuthClient>;
      const options = mockNodeOAuthClient.mock.calls[0][0];

      await options.sessionStore.set('testSub', {
        dpopJwk: { kty: 'EC', crv: 'P-256' },
        tokenSet: {
          iss: 'https://example.com',
          sub: 'testSub',
          aud: 'client123',
          scope: 'read write',
          access_token: 'test-access-token',
          token_type: 'Bearer',
        },
      });
      await options.sessionStore.del('testSub');
      expect(options.sessionStore.get('testSub')).resolves.toBeUndefined();
    });
  });

  describe('constructor', () => {
    it('should throw an error if verify callback is not provided', () => {
      expect(() => new ATprotocolStrategy({ oauthClient: mockOAuthClient }, null)).toThrow(
        'ATprotocolStrategy requires a verify callback',
      );
    });

    it('should set the name to "atprotocol"', () => {
      expect(strategy.name).toBe('atprotocol');
    });
  });

  describe('refreshAccessToken', () => {
    it('should refresh the access token', async () => {
      const mockSession = {
        profile: mockProfile,
      };
      const mockTokenSet = {
        access_token: 'new-access-token',
        refresh_token: 'new-refresh-token',
        expires_at: 1234567890,
      };

      mockOAuthClient.restore.mockResolvedValue({
        getTokenSet: jest.fn().mockResolvedValue(mockTokenSet),
      });

      const result = await strategy.refreshAccessToken(mockSession);

      expect(result).toEqual({
        ...mockSession,
        accessToken: 'new-access-token',
        refreshToken: 'new-refresh-token',
        tokenExpiry: 1234567890,
      });
    });
  });

  describe('authenticate', () => {
    it('should fail if state parameter is missing', async () => {
      const req = { query: {} };
      strategy.fail = jest.fn();

      await strategy.authenticate(req);

      expect(strategy.fail).toHaveBeenCalledWith({ message: 'Missing state parameter' }, 400);
    });

    it('should fail if state is invalid or expired', async () => {
      const req = { query: { state: 'invalid-state' } };
      strategy.fail = jest.fn();

      await strategy.authenticate(req);

      expect(strategy.fail).toHaveBeenCalledWith({ message: 'Invalid or expired state' }, 400);
    });

    it('should fail if callback is passed an error', async () => {
      const req = { query: { state: 'valid-state', code: 'valid-code' } };

      const mockCallbackResult = {
        session: {
          did: 'did:example:12',
          getTokenSet: jest.fn().mockResolvedValue({
            access_token: 'test-access-token',
            refresh_token: 'test-refresh-token',
            expires_at: 1234567890,
          }),
        },
      };
      mockOAuthClient.callback.mockResolvedValue(mockCallbackResult);

      const error = new Error('Callback error');

      strategy.verify = jest.fn(function ({
        req,
        accessToken,
        refreshToken,
        profile,
        tokenExpiry,
        callback,
      }) {
        return callback(error);
      });

      await strategy.authorize(mockProfile.handle, req.query.state);

      await strategy.authenticate(req);

      expect(strategy.error).toHaveBeenCalledWith(error);
    });

    it('should fail if callback is not passed a user', async () => {
      const req = { query: { state: 'valid-state', code: 'valid-code' } };

      const mockCallbackResult = {
        session: {
          did: 'did:example:12',
          getTokenSet: jest.fn().mockResolvedValue({
            access_token: 'test-access-token',
            refresh_token: 'test-refresh-token',
            expires_at: 1234567890,
          }),
        },
      };
      mockOAuthClient.callback.mockResolvedValue(mockCallbackResult);

      const info = { message: 'No user found' };
      strategy.verify = jest.fn(function ({
        req,
        accessToken,
        refreshToken,
        profile,
        tokenExpiry,
        callback,
      }) {
        return callback(null, null, info);
      });

      await strategy.authorize(mockProfile.handle, req.query.state);

      await strategy.authenticate(req);

      expect(strategy.fail).toHaveBeenCalledWith(info);
    });

    it('should successfully authenticate with valid state and code', async () => {
      const req = { query: { state: 'valid-state', code: 'valid-code' } };
      const params = new URLSearchParams(req.query as Record<string, string>);

      const mockCallbackResult = {
        session: {
          did: 'did:example:12',
          getTokenSet: jest.fn().mockResolvedValue({
            access_token: 'test-access-token',
            refresh_token: 'test-refresh-token',
            expires_at: 1234567890,
          }),
        },
      };
      mockOAuthClient.callback.mockResolvedValue(mockCallbackResult);

      const mockSuccessResult = {
        accessToken: 'test-access-token',
        refreshToken: 'test-refresh-token',
        tokenExpiry: 1234567890,
        profile: {
          mockProfile,
        },
      };

      strategy.verify = jest.fn(function ({
        req,
        accessToken,
        refreshToken,
        profile,
        tokenExpiry,
        callback,
      }) {
        return callback(null, mockSuccessResult, null);
      });

      await strategy.authorize(mockProfile.handle, req.query.state);

      await strategy.authenticate(req, { returnRawProfile: true });

      expect(mockOAuthClient.callback).toHaveBeenCalledWith(params);
      expect(strategy.verify).toHaveBeenCalled();
      expect(strategy.success).toHaveBeenCalledWith(mockSuccessResult, null);
    });

    it('should fail if there is an OAuthCallbackError thrown', async () => {
      const req = { query: { state: 'valid-state', code: 'valid-code' } };
      const params = new URLSearchParams(req.query as Record<string, string>);
      const error = new OAuthCallbackError(params);

      mockOAuthClient.callback.mockRejectedValue(error);

      await strategy.authorize('test-handle', req.query.state);
      await strategy.authenticate(req);

      expect(mockOAuthClient.callback).toHaveBeenCalledWith(params);
      expect(strategy.fail).toHaveBeenCalledWith({ message: error.message }, 401);
    });

    it('should handle errors during authentication process', async () => {
      const req = { query: { state: 'valid-state', code: 'valid-code' } };
      const params = new URLSearchParams(req.query as Record<string, string>);

      mockOAuthClient.callback.mockRejectedValue(new Error('Authentication failed'));

      await strategy.authorize('test-handle', req.query.state);
      await strategy.authenticate(req);

      expect(mockOAuthClient.callback).toHaveBeenCalledWith(params);
      expect(strategy.error).toHaveBeenCalledWith(new Error('Authentication failed'));
    });
  });

  describe('authorize', () => {
    it('should set state and return authorization URL', async () => {
      const handle = 'test-handle';
      const state = 'test-state';
      const mockAuthUrl = 'https://example.com/auth';

      mockOAuthClient.authorize.mockResolvedValue(mockAuthUrl);

      const result = await strategy.authorize(handle, state);

      expect(result).toBe(mockAuthUrl);
    });
  });

  describe('logout', () => {
    it('should delete session and call req.logout', async () => {
      const req = {
        user: mockProfile,
        logout: jest.fn((callback) => callback()),
      };
      const done = jest.fn();

      await strategy.logout(req, done);

      expect(req.logout).toHaveBeenCalled();
      expect(done).toHaveBeenCalled();
    });
  });

  describe('createATProtocolLoginMiddleware', () => {
    it('should create middleware that redirects to the authorization URL', async () => {
      const req = { query: { state: 'test-state' } };
      const res = { redirect: jest.fn() };
      const next = jest.fn();
      const mockAuthUrl = 'https://example.com/auth';

      mockOAuthClient.authorize.mockResolvedValue(mockAuthUrl);
      mockOAuthClient.clientMetadata = clientMetadata;

      const middleware = createATProtocolLoginMiddleware({
        oauthClient: mockOAuthClient,
      });

      const expressReq = {
        ...req,
        on: jest.fn(),
        get: jest.fn(),
        header: jest.fn(),
        accepts: jest.fn(),
        session: {},
      } as unknown as ExpressRequestWithSession;

      await middleware(expressReq, res as any, next);

      expect(res.redirect).toHaveBeenCalledWith(mockAuthUrl);
    });

    it('show throw an error if authorize fails', async () => {
      const req = { query: { handle: 'test-handle' } };
      const res = { redirect: jest.fn() };
      const next = jest.fn();

      const expressReq = {
        ...req,
        on: jest.fn(),
        get: jest.fn(),
        header: jest.fn(),
        accepts: jest.fn(),
        session: {},
      } as unknown as ExpressRequestWithSession;

      const error = new Error('Missing state parameter');
      mockOAuthClient.authorize.mockRejectedValue(error);
      mockOAuthClient.clientMetadata = clientMetadata;

      const middleware = createATProtocolLoginMiddleware({
        oauthClient: mockOAuthClient,
      });

      await new Promise<void>((resolve) => {
        middleware(expressReq, res as any, (err) => {
          next(err);
          resolve();
        });
      });

      expect(next).toHaveBeenCalledWith(error);
    });
  });
});
