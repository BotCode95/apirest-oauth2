'use strict';

const passport = require('passport');

module.exports.info = [
  passport.authenticate('bearer', { session: false }),
  (req, res) => {
    
    res.json({ client_id: reqt.user.id, name: req.user.name, scope: req.authInfo.scope });
  }
];
