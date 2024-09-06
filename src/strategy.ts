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

const STATE = new Map();
const SESSION = new Map();

const DEFAULT_HANDLE_RESOLVER = 'https://bsky.social';

const createOAuthClient = (options: ATprotocolOptions) => {
  const nodeOAuthClientOptions: NodeOAuthClientOptions = {
    clientMetadata: options.clientMetadata,
    keyset: options.keyset,
    // optional if only one instance is running
    requestLock: null,
    stateStore: {
      async set(key: string, internalState: NodeSavedState): Promise<void> {
        STATE.set(key, internalState);
      },
      async get(key: string): Promise<NodeSavedState | undefined> {
        return STATE.get(key);
      },
      async del(key: string): Promise<void> {
        STATE.delete(key);
      },
    },
    sessionStore: {
      async set(sub: string, sessionData: NodeSavedSession) {
        SESSION.set(sub, sessionData);
      },
      async get(sub: string) {
        return SESSION.get(sub);
      },
      async del(sub: string) {
        SESSION.delete(sub);
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

  constructor(options: ATprotocolStrategyOptions, verify: VerifyCallback) {
    super();

    if (!verify) {
      throw new TypeError('ATprotocolStrategy requires a verify callback');
    }

    this.verify = verify;
    this.options = options;
    this.oauthClient = options.oauthClient;
  }

  async refreshAccessToken(session: PassportSession): Promise<PassportSession> {
    const agent = await this.oauthClient.restore(session.profile.did);
    const tokenSet = await agent.getTokenSet();

    return {
      ...session,
      accessToken: tokenSet.access_token,
      refreshToken: tokenSet.refresh_token,
      tokenExpiry: tokenSet.expires_at,
    };
  }

  async authenticate(req: ExpressRequestWithSession, options?: StrategyOptions) {
    const callbackParams = new URLSearchParams(req.query as Record<string, string>);

    const state = callbackParams.get('state');
    if (!state) {
      return this.fail({ message: 'Missing state parameter' }, 400);
    }

    const stateData = await STATE.get(state);
    if (!stateData) {
      return this.fail({ message: 'Invalid or expired state' }, 400);
    }

    try {
      const result: CallbackResult = await this.oauthClient.callback(callbackParams);
      const agent = new Agent(result.session);
      const userProfile: AppBskyActorGetProfile.Response = await agent.getProfile({
        actor: result.session.did,
      });
      const profile = options?.returnRawProfile
        ? userProfile.data
        : normalizeProfile(userProfile.data);

      const tokenSet = await result.session.getTokenSet();
      const accessToken = tokenSet.access_token;
      const refreshToken = tokenSet.refresh_token;
      const tokenExpiry = tokenSet.expires_at;

      const params: VerifyCallbackParams = {
        profile,
        accessToken,
        refreshToken,
        tokenExpiry,
        callback: (err, user, info) => {
          if (err) {
            return this.error(err);
          }
          if (!user) {
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
        return this.fail({ message: err.message }, 401);
      }
      return this.error(err);
    } finally {
      STATE.delete(state);
    }
  }

  async authorize(handle: string, state: string) {
    await STATE.set(state, { createdAt: Date.now() });
    return this.oauthClient.authorize(handle, { state });
  }

  async logout(req: ExpressRequestWithSession, done: (err: any) => void) {
    if (req.user) {
      const did = (req.user as ATprotocolProfile).did;
      SESSION.delete(did);
    }
    req.logout(done);
  }
}

function createATProtocolLoginMiddleware({
  oauthClient,
  prompt,
  uiLocales,
}: CreateLoginMiddlewareParams) {
  return (req: ExpressRequestWithSession, res: Response, next) => {
    // revoke authentication request if the connection is closed
    const ac = new AbortController();
    req.on('close', () => ac.abort());

    const state = req.query.state?.toString() || crypto.randomBytes(256).toString();
    const handle = req.query.handle?.toString() || DEFAULT_HANDLE_RESOLVER;

    oauthClient
      .authorize(handle, {
        signal: ac.signal,
        state,
        prompt: prompt || 'consent',
        scope: oauthClient.clientMetadata.scope,
        ui_locales: uiLocales,
      })
      .then((url) => res.redirect(url.toString()))
      .catch(next);
  };
}

export { createOAuthClient, createATProtocolLoginMiddleware, ATprotocolStrategy };
