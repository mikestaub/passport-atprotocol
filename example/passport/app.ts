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
} = require('../../dist/index');

const app = express();

app.use('/static', express.static(path.join(__dirname, 'static')));

app.use(
  session({
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: true,
  }),
);

const ENDPOINT = 'https://b6f0-2601-18f-27f-b590-2c31-b649-112a-116d.ngrok-free.app';

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
