'use strict';

const oauth2orize = require('@poziworld/oauth2orize');
const passport = require('passport');
const login = require('connect-ensure-login');
const db = require('../db');
const utils = require('../utils');

// createServer OAuth 2.0 
const server = oauth2orize.createServer();

server.serializeClient((client, done) => done(null, client.id));

server.deserializeClient((id, done) => {
  db.clients.findById(id, (error, client) => {
    if (error) return done(error);
    return done(null, client);
  });
});

function issueTokens(userId, clientId, done) {
  db.users.findById(userId, (error, user) => {
    const accessToken = utils.getUid(256);
    const refreshToken = utils.getUid(256);
    db.accessTokens.save(accessToken, userId, clientId, (error) => {
      if (error) return done(error);
      db.refreshTokens.save(refreshToken, userId, clientId, (error) => {
        if (error) return done(error);
        
        const params = { username: user.name };
        return done(null, accessToken, refreshToken, params);
      });
    });
  });
}

server.grant(oauth2orize.grant.code((client, redirectUri, user, ares, done) => {
  const code = utils.getUid(16);
  db.authorizationCodes.save(code, client.id, redirectUri, user.id, user.username, (error) => {
    if (error) return done(error);
    return done(null, code);
  });
}));

server.grant(oauth2orize.grant.token((client, user, ares, done) => {
  issueTokens(user.id, client.clientId, done);
}));

server.exchange(oauth2orize.exchange.code((client, code, redirectUri, done) => {
  db.authorizationCodes.find(code, (error, authCode) => {
    if (error) return done(error);
    if (client.id !== authCode.clientId) return done(null, false);
    if (redirectUri !== authCode.redirectUri) return done(null, false);

    issueTokens(authCode.userId, client.clientId, done);
  });
}));

server.exchange(oauth2orize.exchange.password((client, username, password, scope, done) => {
  // Validate the client
  db.clients.findByClientId(client.clientId, (error, localClient) => {
    if (error) return done(error);
    if (!localClient) return done(null, false);
    if (localClient.clientSecret !== client.clientSecret) return done(null, false);
    // Validate the user
    db.users.findByUsername(username, (error, user) => {
      if (error) return done(error);
      if (!user) return done(null, false);
      if (password !== user.password) return done(null, false);
      // Everything validated, return the token
      issueTokens(user.id, client.clientId, done);
    });
  });
}));

server.exchange(oauth2orize.exchange.clientCredentials((client, scope, done) => {
  // Validate the client
  db.clients.findByClientId(client.clientId, (error, localClient) => {
    if (error) return done(error);
    if (!localClient) return done(null, false);
    if (localClient.clientSecret !== client.clientSecret) return done(null, false);
    
    issueTokens(null, client.clientId, done);
  });
}));

// usando nuevos tokens y removiendo los viejos
server.exchange(oauth2orize.exchange.refreshToken((client, refreshToken, scope, done) => {
  db.refreshTokens.find(refreshToken, (error, token) => {
    if (error) return done(error);
    issueTokens(token.id, client.id, (err, accessToken, refreshToken) => {
      if (err) {
        done(err, null, null);
      }
      db.accessTokens.removeByUserIdAndClientId(token.userId, token.clientId, (err) => {
        if (err) {
          done(err, null, null);
        }
        db.refreshTokens.removeByUserIdAndClientId(token.userId, token.clientId, (err) => {
          if (err) {
            done(err, null, null);
          }
          done(null, accessToken, refreshToken);
        });
      });
    });
  });
}));


//Exports

module.exports.authorization = [
  login.ensureLoggedIn(),
  server.authorization((clientId, redirectUri, done) => {
    db.clients.findByClientId(clientId, (error, client) => {
      if (error) return done(error);
    
      return done(null, client, redirectUri);
    });
  }, (client, user, done) => {
   
    if (client.isTrusted) return done(null, true);

    db.accessTokens.findByUserIdAndClientId(user.id, client.clientId, (error, token) => {
     
      if (token) return done(null, true);

      // Otherwise ask user
      return done(null, false);
    });
  }),
  (request, response) => {
    response.render('dialog', { transactionId: request.oauth2.transactionID, user: request.user, client: request.oauth2.client });
  },
];


module.exports.decision = [
  login.ensureLoggedIn(),
  server.decision(),
];

module.exports.token = [
  passport.authenticate(['basic', 'oauth2-client-password'], { session: false }),
  server.token(),
  server.errorHandler(),
];
