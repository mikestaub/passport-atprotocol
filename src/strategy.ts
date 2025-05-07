import { Strategy } from 'passport-strategy';
import { Response } from 'express';
import {
  NodeOAuthClient,
  NodeOAuthClientOptions,
  OAuthSession,
  NodeSavedState,
  NodeSavedSession,
  OAuthCallbackError,
} from '@atproto/oauth-client-node';
import { Agent, AppBskyActorGetProfile } from '@atproto/api';
import * as crypto from 'crypto';

import { normalizeProfile } from './normalizeProfile';
import { InMemoryStateStore, InMemorySessionStore } from './storage';
import { ConsoleLogger, Logger } from './logger';
import {
  ATprotocolOptions,
  ATprotocolStrategyOptions,
  VerifyCallback,
  VerifyCallbackParams,
  ATprotocolProfile,
  CreateLoginMiddlewareParams,
  ExpressRequestWithSession,
  PassportSession,
  StrategyOptions,
} from './types';

type CallbackResult = {
  session: OAuthSession;
  state: string | null;
};

const DEFAULT_STATE_STORE = new InMemoryStateStore();
const DEFAULT_SESSION_STORE = new InMemorySessionStore();

const DEFAULT_HANDLE_RESOLVER = 'https://bsky.social';

const createOAuthClient = (options: ATprotocolOptions) => {
  const logger = options.logger || new ConsoleLogger();
  
  const nodeOAuthClientOptions: NodeOAuthClientOptions = {
    clientMetadata: options.clientMetadata,
    keyset: options.keyset,
    // optional if only one instance is running
    requestLock: null,
    stateStore: options.stateStore || {
      async set(key: string, internalState: NodeSavedState): Promise<void> {
        logger.debug('Storing state', { key });
        DEFAULT_STATE_STORE.set(key, internalState);
      },
      async get(key: string): Promise<NodeSavedState | undefined> {
        logger.debug('Retrieving state', { key });
        return DEFAULT_STATE_STORE.get(key);
      },
      async del(key: string): Promise<void> {
        logger.debug('Deleting state', { key });
        DEFAULT_STATE_STORE.del(key);
      },
    },
    sessionStore: options.sessionStore || {
      async set(sub: string, sessionData: NodeSavedSession) {
        logger.debug('Storing session', { sub });
        DEFAULT_SESSION_STORE.set(sub, sessionData);
      },
      async get(sub: string) {
        logger.debug('Retrieving session', { sub });
        return DEFAULT_SESSION_STORE.get(sub);
      },
      async del(sub: string) {
        logger.debug('Deleting session', { sub });
        DEFAULT_SESSION_STORE.del(sub);
      },
    },
  };

  return new NodeOAuthClient(nodeOAuthClientOptions);
};

class ATprotocolStrategy extends Strategy {
  name = 'atprotocol';
  private oauthClient: NodeOAuthClient;
  private verify: VerifyCallback;
  private options: ATprotocolStrategyOptions;
  private logger: Logger;

  constructor(options: ATprotocolStrategyOptions, verify: VerifyCallback) {
    super();

    if (!verify) {
      throw new TypeError('ATprotocolStrategy requires a verify callback');
    }

    this.verify = verify;
    this.options = options;
    this.oauthClient = options.oauthClient;
    this.logger = options.logger || new ConsoleLogger();
  }

  async refreshAccessToken(session: PassportSession): Promise<PassportSession> {
    try {
      this.logger.debug('Refreshing access token', { did: session.profile.did });
      
      this.logger.debug('Using existing token data');
      
      return {
        ...session,
        accessToken: session.accessToken,
        refreshToken: session.refreshToken,
        tokenExpiry: new Date(Date.now() + 3600 * 1000).toISOString(), // 1 hour from now
      };
    } catch (error) {
      this.logger.error('Failed to refresh access token', { error });
      throw error;
    }
  }

  async authenticate(req: ExpressRequestWithSession, options?: StrategyOptions) {
    const callbackParams = new URLSearchParams(req.query as Record<string, string>);
    
    this.logger.debug('Authenticating', { query: req.query });

    const state = callbackParams.get('state');
    if (!state) {
      this.logger.warn('Missing state parameter');
      return this.fail({ message: 'Missing state parameter' }, 400);
    }

    try {
      const stateData = await DEFAULT_STATE_STORE.get(state);
      if (!stateData) {
        this.logger.warn('Invalid or expired state', { state });
        return this.fail({ message: 'Invalid or expired state' }, 400);
      }

      try {
        this.logger.debug('Processing callback', { state });
        const result: CallbackResult = await this.oauthClient.callback(callbackParams);
        const agent = new Agent(result.session);
        
        this.logger.debug('Fetching user profile', { did: result.session.did });
        const userProfile: AppBskyActorGetProfile.Response = await agent.getProfile({
          actor: result.session.did,
        });
        
        const profile = options?.returnRawProfile
          ? userProfile.data
          : normalizeProfile(userProfile.data);

        const accessToken = 'access_token_placeholder';
        const refreshToken = 'refresh_token_placeholder';
        const tokenExpiry = new Date(Date.now() + 3600 * 1000).toISOString(); // 1 hour from now

        this.logger.debug('Authentication successful', { 
          did: result.session.did, 
          handle: profile.handle 
        });

        const params: VerifyCallbackParams = {
          profile,
          accessToken,
          refreshToken,
          tokenExpiry,
          callback: (err, user, info) => {
            if (err) {
              this.logger.error('Verification error', { error: err });
              return this.error(err);
            }
            if (!user) {
              this.logger.warn('Verification failed', { info });
              return this.fail(info);
            }
            return this.success(user, info);
          },
        };

        if (this.options.passReqToCallback) {
          params.req = req;
        }

        this.verify(params);
      } catch (err) {
        if (err instanceof OAuthCallbackError) {
          this.logger.warn('OAuth callback error', { message: err.message });
          return this.fail({ message: err.message }, 401);
        }
        this.logger.error('Authentication error', { error: err });
        return this.error(err);
      }
    } finally {
      this.logger.debug('Cleaning up state', { state });
      DEFAULT_STATE_STORE.del(state);
    }
  }

  async authorize(handle: string, state: string) {
    this.logger.debug('Authorizing', { handle, state });
    await DEFAULT_STATE_STORE.set(state, { createdAt: Date.now() });
    return this.oauthClient.authorize(handle, { state });
  }

  async logout(req: ExpressRequestWithSession, done: (err: any) => void) {
    this.logger.debug('Logging out');
    try {
      if (req.user) {
        const did = (req.user as ATprotocolProfile).did;
        this.logger.debug('Deleting session', { did });
        DEFAULT_SESSION_STORE.del(did);
      }
      req.logout(done);
    } catch (error) {
      this.logger.error('Logout error', { error });
      done(error);
    }
  }
}

function createATProtocolLoginMiddleware({
  oauthClient,
  prompt,
  uiLocales,
  logger = new ConsoleLogger(),
}: CreateLoginMiddlewareParams & { logger?: Logger }) {
  return (req: ExpressRequestWithSession, res: Response, next) => {
    logger.debug('Login middleware initiated');
    // revoke authentication request if the connection is closed
    const ac = new AbortController();
    req.on('close', () => {
      logger.debug('Request closed, aborting authorization');
      ac.abort();
    });

    const state = req.query.state?.toString() || crypto.randomBytes(256).toString();
    const handle = req.query.handle?.toString() || DEFAULT_HANDLE_RESOLVER;
    
    logger.debug('Authorizing', { handle, state });

    oauthClient
      .authorize(handle, {
        signal: ac.signal,
        state,
        prompt: prompt || 'consent',
        scope: oauthClient.clientMetadata.scope,
        ui_locales: uiLocales,
      })
      .then((url) => res.redirect(url.toString()))
      .catch((error) => {
        logger.error('Authorization error', { error });
        next(error);
      });
  };
}

export { createOAuthClient, createATProtocolLoginMiddleware, ATprotocolStrategy };
