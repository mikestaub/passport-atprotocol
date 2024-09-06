import { Request } from 'express';
import { Session } from 'express-session';
import { NodeOAuthClient, ClientMetadata, AuthorizeOptions } from '@atproto/oauth-client-node';
import { AppBskyActorDefs } from '@atproto/api';
import { JoseKey } from '@atproto/jwk-jose';

export interface ATprotocolOptions {
  clientMetadata: ClientMetadata;
  keyset: JoseKey[];
}

export interface ExpressRequestWithSession extends Request {
  session: Session;
}

export interface ATprotocolStrategyOptions {
  oauthClient: NodeOAuthClient;
  passReqToCallback?: boolean;
}

export type CreateLoginMiddlewareParams = {
  oauthClient: NodeOAuthClient;
  uiLocales?: string;
  prompt?: AuthorizeOptions['prompt'];
};

export interface ATprotocolProfile extends AppBskyActorDefs.ProfileViewDetailed {}

// Normalized profile: http://www.passportjs.org/docs/profile/
// With intent to make this backwards compatible we clone the original data format
export type PassportATprotocolProfile = ATprotocolProfile & {
  provider: 'atprotocol';
};

export type DoneCallback = (err: any, user: any, info: any) => void;

export type CallbackWithRequest = (
  req: Request,
  user: PassportATprotocolProfile,
  done: DoneCallback,
) => void;
export type CallbackWithoutRequest = (user: PassportATprotocolProfile, done: DoneCallback) => void;

export type PassportSession = {
  accessToken: string;
  refreshToken: string;
  tokenExpiry: string;
  profile: ATprotocolProfile;
};

export type StrategyOptions = {
  returnRawProfile?: boolean;
};

export type VerifyCallbackParams = {
  req?: Request;
  accessToken: string;
  refreshToken: string;
  tokenExpiry: string;
  profile: ATprotocolProfile;
  callback: (err: any, user: any, info: any) => void;
};

export type VerifyCallback = (params: VerifyCallbackParams) => void;
