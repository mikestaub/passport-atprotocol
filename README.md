# passport-atprotocol

[![GitHub license](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/mikestaub/passport-atprotocol/blob/main/LICENSE)  [![npm version](https://img.shields.io/npm/v/passport-atprotocol.svg?style=flat)](https://www.npmjs.com/package/passport-atprotocol)  [![Coverage Status](https://coveralls.io/repos/github/mikestaub/passport-atprotocol/badge.svg?branch=main)](https://coveralls.io/github/mikestaub/passport-atprotocol?branch=main) [![Discord](https://img.shields.io/discord/1097580399187738645?style=flat&logo=discord&logoColor=white)](https://discord.gg/tCD8MMfq)

## WARNING: this library is currently in development and should not be used in production

## Quickstart

clone this repo
```
git clone https://github.com/mikestaub/passport-atprotocol.git
cd passport-atprotocol
yarn install
```

generate your server keys
```
npm run generate-keys
cat .env
```

copy them into your app environment

create your app metadata:
```
{
    "client_id": "YOUR_ENDPOINT/static/client-metadata.json",
    "client_name": "My Passport atproto OAuth App",
    "client_uri": "YOUR_ENDPOINT",
    "redirect_uris": ["YOUR_ENDPOINT/auth/atprotocol/callback"],
    "logo_uri": "YOUR_ENDPOINT/logo.png",
    "tos_uri": "YOUR_ENDPOINT/tos",
    "policy_uri": "YOUR_ENDPOINT/policy",
    "jwks_uri": "YOUR_ENDPOINT/auth/atprotocol/jwks.json",
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
    "scope": "atproto transition:generic",
    "token_endpoint_auth_method": "private_key_jwt",
    "token_endpoint_auth_signing_alg": "ES256",
    "application_type": "web",
    "dpop_bound_access_tokens": true
}
```

modify your app to implement the passport-atprotocol routes and logic. See example/passport for a full working demo

```
const express = require('express');
const passport = require('passport');
const session = require('express-session');
const path = require('path');
const { JoseKey } = require('@atproto/jwk-jose');

require('dotenv').config();

const {
  createOAuthClient,
  createATProtocolLoginMiddleware,
  ATprotocolStrategy,
} = require('passport-atprotocol');

const app = express();

app.use('/static', express.static(path.join(__dirname, 'static')));

app.use(
  session({
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: true,
  }),
);

const ENDPOINT = 'https://your.public.endpoint';

async function setupKeys() {
  const keyset = [
    await JoseKey.fromImportable(process.env.PRIVATE_KEY_1),
    await JoseKey.fromImportable(process.env.PRIVATE_KEY_2),
    await JoseKey.fromImportable(process.env.PRIVATE_KEY_3),
  ];
  return keyset;
}

setupKeys()
  .then((keyset) => {
    // Note: this exact json must be publically available at the URL specified by client_id
    const clientMetadata = {
      client_name: 'My Passport atproto OAuth App',
      client_uri: ENDPOINT,
      client_id: `${ENDPOINT}/static/client-metadata.json`,
      logo_uri: `${ENDPOINT}/logo.png`,
      tos_uri: `${ENDPOINT}/tos`,
      policy_uri: `${ENDPOINT}/policy`,
      jwks_uri: `${ENDPOINT}/auth/atprotocol/jwks.json`,
      redirect_uris: [`${ENDPOINT}/auth/atprotocol/callback`],
      grant_types: ['authorization_code'],
      response_types: ['code'],
      scope: 'atproto transition:generic',
      token_endpoint_auth_method: 'private_key_jwt',
      token_endpoint_auth_signing_alg: 'ES256',
      application_type: 'web',
      dpop_bound_access_tokens: true,
    };

    // Note: this client uses memory storage, in production consider providing your own implementation
    const oauthClient = createOAuthClient({ clientMetadata, keyset });

    const strategy = new ATprotocolStrategy(
      {
        oauthClient,
        passReqToCallback: true,
      },
      function ({ req, accessToken, refreshToken, profile, tokenExpiry, callback }) {
        if (req) {
          req.user = profile;
        }

        const passportUserSession = {
          profile,
          accessToken,
          refreshToken,
          tokenExpiry,
        };

        // async verification, for effect
        process.nextTick(function () {
          return callback(null, passportUserSession, null);
        });
      },
    );

    app.use(passport.initialize());
    app.use(passport.session());

    passport.use(strategy);

    passport.serializeUser((user, done) => {
      done(null, user);
    });

    passport.deserializeUser((user, done) => {
      if (!user?.tokenExpiry) {
        return done(null, user);
      }

      const expiryDate = new Date(user.tokenExpiry);
      const currentDate = new Date();

      if (currentDate <= expiryDate) {
        return done(null, user);
      }

      strategy
        .refreshAccessToken(user)
        .then((updatedUser) => done(null, updatedUser))
        .catch((err) => done(err));
    });

    app.get('/auth/atprotocol/jwks.json', (req, res) => res.json(oauthClient.jwks));

    // Note: you can call this endpoint with a ?handle=someuser.social query parameter to login as that user
    app.get('/auth/atprotocol/login', createATProtocolLoginMiddleware({ oauthClient }));

    app.get(
      '/auth/atprotocol/callback',
      // Note: use returnRawProfile=true if you want all the full profile stored in the session
      // passport.authenticate('atprotocol', { returnRawProfile: true }),
      passport.authenticate('atprotocol'),
      (req, res) => {
        res.redirect('/');
      },
    );

    app.get('/auth/atprotocol/logout', (req, res) => {
      req.logout((err) => {
        if (err) {
          console.error('Logout error:', err);
        }
        res.redirect('/');
      });
    });

    app.get('/auth/atprotocol/revoke', ensureAuthenticated, (req, res) => {
      oauthClient
        .revoke(req.user.profile.did)
        .then(() => {
          req.logout((err) => {
            if (err) {
              console.error('Logout error:', err);
            }
            res.redirect('/');
          });
        })
        .catch((error) => {
          res.status(500).send('Failed to revoke token: ' + error.message);
        });
    });

    function ensureAuthenticated(req, res, next) {
      if (req.isAuthenticated()) {
        return next();
      } else {
        res.sendStatus(401);
      }
    }

    app.get('/api/profile', ensureAuthenticated, (req, res) => {
      res.json(req.user.profile);
    });

    app.get('*', (req, res) => {
      res.sendFile(path.join(__dirname, 'static', 'index.html'));
    });

    const PORT = process.env.PORT || 1234;
    app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
  })
  .catch(console.error);

```

## Rotate server keys

Generally they should be rotated every 90 days for security
( context: https://darutk.medium.com/illustrated-dpop-oauth-access-token-security-enhancement-801680d761ff)
```
npm run rotate-keys
```

## Production Considerations

- use a database to store session and user data
- use NodeOAuthClientOptions.requestLock=true if running multiple server instances
- implement proper key rotation
- implement proper token revocation
- implement proper error handling
- implement proper logging


