'use strict';

const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const BasicStrategy = require('passport-http').BasicStrategy;
const ClientPasswordStrategy = require('passport-oauth2-client-password').Strategy;
const BearerStrategy = require('passport-http-bearer').Strategy;
const db = require('../db');

passport.use(new LocalStrategy(
  (username, password, done) => {
    db.users.findByUsername(username, (error, user) => {
      if (error) return done(error);
      if (!user) return done(null, false);
      if (user.password !== password) return done(null, false);
      return done(null, user);
    });
  }
));

passport.serializeUser((user, done) =>  done(null, user.id));

passport.deserializeUser((id, done) => {
  db.users.findById(id, (error, user) => done(error, user));
});


function verifyClient(clientId, clientSecret, done) {
  db.clients.findByClientId(clientId, (error, client) => {
    if (error) return done(error);
    if (!client) return done(null, false);
    if (client.clientSecret !== clientSecret) return done(null, false);
    return done(null, client);
  });
}

passport.use(new BasicStrategy(verifyClient));

passport.use(new ClientPasswordStrategy(verifyClient));

passport.use(new BearerStrategy(
  (accessToken, done) => {
    db.accessTokens.find(accessToken, (error, token) => {
      if (error) return done(error);
      if (!token) return done(null, false);
      if (token.userId) {
        db.users.findById(token.userId, (error, user) => {
          if (error) return done(error);
          if (!user) return done(null, false);
       
          done(null, user, { scope: '*' });
        });
      } else {
      
        db.clients.findByClientId(token.clientId, (error, client) => {
          if (error) return done(error);
          if (!client) return done(null, false);
         
          done(null, client, { scope: '*' });
        });
      }
    });
  }
));
