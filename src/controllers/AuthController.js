var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var JwtStrategy = require('passport-jwt').Strategy;
var OAuthAccessTokenStrategy = require('passport-oauth-access-token').Strategy;
var Promise = require('es6-promise').Promise;
var unless = require('express-unless');
var crypto = require('crypto');
var jwt = require('jsonwebtoken');
var scmp = require('scmp');

var emitter = require('../emitter');
var errors = require('../errors');
var db = require('../db');

///////////////////////////
//        HELPERS        //
///////////////////////////

function authenticate(ignoredPaths, options) {
  var middleware = function(req, res, next) {
    var isLoginRoute = req.url === options.routes.login;
    var isLoginOAuthRoute = req.url === options.routes.loginOAuth;
    var isOAuthProfileRoute = req.url === options.routes.oAuthProfile;
    var authenticator;

    // use local strategy for login request
    if (isLoginRoute) {
      authenticator = getAuthenticator('local');
    } else if (isLoginOAuthRoute || isOAuthProfileRoute) {
      authenticator = getAuthenticator('oAuthAccessToken');
    } else {
      authenticator = getAuthenticator('jwt');
    }

    req.log.info('Emitting before-authenticate event');
    emitter.once('before-authenticate', function() {
      req.log.info('Received before-authenticate event');

      authenticator(req, res, function(err) {
        var args = arguments;

        if (!err && req.user) {
          req.log.info('Emitting after-authenticate event');

          // CAVEAT: req.user can be a user object OR a userId string for this event
          emitter.once('after-authenticate', function() {
            req.log.info('Received after-authenticate event');
            next.apply(this, args);
          }).emit('after-authenticate', req, res);
        } else {
          next.apply(this, args);
        }
      });
    }).emit('before-authenticate', req, res);
  };

  middleware.unless = unless;

  return middleware.unless({
    path: ignoredPaths
  });
}

function hasLoginAttemptLimit(options) {
  return options.loginAttemptLimit > 0;
}

function isLoginAttemptLocked(user, loginAttempts, options) {
  if (hasLoginAttemptLimit(options)) {
    var loginAttemptLockTime = db.adaptor.getLoginAttemptLockTime(user);

    if (loginAttemptLockTime) {
      var ms = options.loginAttemptLockDuration * 60000;

      // should not be considered locked if it's past the lock duration
      return Date.now() < loginAttemptLockTime + ms;
    }

    return loginAttempts >= options.loginAttemptLimit;
  }

  return false;
}

function generateToken(req, res, options) {
  return new Promise(function(resolve) {
    req.log.info('Emitting jwt-payload event');
    emitter.once('jwt-payload', function(rq, rs, payload) {
      req.log.info('Received jwt-payload event');
      resolve(jwt.sign({}, options.secretOrKey, payload));
    }).emit('jwt-payload', req, res, {
      subject: db.adaptor.getId(req.user),
      expiresInSeconds: options.tokenExpiresInSeconds,
      expiresInMinutes: options.tokenExpiresInMinutes
    });
  });
}

function generateResetPasswordToken(user, options) {
  return new Promise(function(resolve, reject) {
    crypto.randomBytes(options.resetPasswordTokenLength, function(err, buffer) {
      if (err) {
        return reject(err);
      }

      var resetToken = buffer.toString('hex');

      getResetPasswordHashForToken(resetToken, options).then(function(resetPasswordHash) {
        return db.adaptor.update(user, {
          resetPasswordHash: resetPasswordHash,
          resetPasswordExpiration: Date.now() + options.resetPasswordExpiration * 60000
        });
      }).then(function() {
        resolve(resetToken);
      }).catch(reject);
    });
  });
}

function getResetPasswordHashForToken(resetToken, options) {
  return new Promise(function(resolve, reject) {
    crypto.pbkdf2(resetToken, '', options.pbkdf2Iterations, options.pbkdf2KeyLength, options.pbkdf2Algorithm,
      function(err, hashRaw) {
        if (err) {
          return reject(err);
        }

        var hash = new Buffer(hashRaw, 'binary').toString(options.encoding);

        return resolve(hash);
      });
  });
}

function authenticatePassword(user, password, options, contextLog) {
  return new Promise(function(resolve, reject) {

    var salt = db.adaptor.getSalt(user);

    if (!salt) {
      return reject(new errors.NoSaltError());
    }

    crypto.pbkdf2(password, salt, options.pbkdf2Iterations, options.pbkdf2KeyLength, options.pbkdf2Algorithm, function(err, hashRaw) {
      if (err) {
        return reject(err);
      }

      var hash = new Buffer(hashRaw, 'binary').toString(options.encoding);

      if (scmp(hash, db.adaptor.getHash(user))) {
        if (hasLoginAttemptLimit(options)) {
          db.adaptor.update(user, {
            loginAttempts: 0,
            lastLogin: Date.now(),
            loginAttemptLockTime: null
          }).then(resolve).catch(function(err) {
            contextLog.error(err);
            resolve(); // resolve anyway
          });
        } else {
          return resolve();
        }
      } else {
        var credsErr = new errors.InvalidCredentialsError();

        maybeSaveLoginAttempt(user, options, contextLog).then(function() {
          reject(credsErr);
        }).catch(function() {
          reject(credsErr);
        });
      }
    });
  });
}

function authenticateUser(user, password, options, contextLog) {
  if (isLoginAttemptLocked(user, db.adaptor.getLoginAttempts(user), options)) {
    var lockedRejection = Promise.reject(new errors.LockedAccountError());

    contextLog.info('Login attempt locked');

    return maybeSaveLoginAttempt(user, options, contextLog).then(function() {
      return lockedRejection;
    }).catch(function() {
      return lockedRejection;
    });
  } else {
    return authenticatePassword(user, password, options, contextLog);
  }
}

function localAuthenticate(options) {
  return function(req, username, password, done) {
    req.log = req.log.child({
      username: username,
      strategy: 'local'
    });

    db.adaptor.findByUsername(username).then(function(user) {
      if (user) {
        req.log = req.log.child({
          username: '', // clear username association with user id in logs
          user: user._id
        });

        req.log.info('Authenticating user...');

        authenticateUser(user, password, options, req.log).then(function() {
          req.log.info('Successfully authenticated user');
          done(null, user);
        }, function(err) {
          req.log.warn(err);
          done(null, false, options.apiEnvelope(null, err));
        }).catch(function(err) {
          req.log.error(err);
          done(err);
        });
      } else {
        var unknownUsernameErr = new errors.UnknownUsernameError(null, username);
        var unknownUsernameData = options.apiEnvelope(null, unknownUsernameErr);

        req.log.warn(unknownUsernameErr);
        done(null, false, options.apiEnvelope(null, unknownUsernameData));
      }
    }).catch(function(err) {
      req.log.error(err);
      done(err);
    });
  };
}

function jwtAuthenticate(options) {
  return function(req, jwtPayload, done) {
    req.log = req.log.child({
      user: jwtPayload.sub,
      strategy: 'jwt'
    });

    db.adaptor.findById(jwtPayload.sub).then(function(user) {
      if (user) {
        req.log.info('Authenticating user...');

        validatePayloadForUser(user, jwtPayload).then(function() {
          req.log.info('Successfully authenticated user');
          done(null, user);
        }, function(err) {
          req.log.warn(err);
          done(null, false, options.apiEnvelope(null, err));
        });
      } else {
        var unknownSubjetErr = new errors.UnknownJWTSubjectError(null, jwtPayload.sub);
        var unknownSubjectData = options.apiEnvelope(null, unknownSubjetErr);

        req.log.warn(unknownSubjetErr);
        done(null, false, options.apiEnvelope(null, unknownSubjectData));
      }
    }).catch(function(err) {
      req.log.error(err);
      done(err);
    });
  };
}

function oAuthAccessTokenAuthenticate(options) {
  return function(req, accessToken, oAuthUserId, done) {
    var isOAuthProfileRoute = ~req.url.indexOf(options.routes.oAuthProfile);
    var oAuthProvider = req.body.oAuthProvider;
    var userPromise;

    req.log = req.log.child({
      oAuthUser: oAuthUserId,
      oAuthProvider: oAuthProvider
    });

    // oauth profile just needs the id
    if (isOAuthProfileRoute) {
      return done(null, oAuthUserId);
    }

    switch (oAuthProvider) {
      case 'google':
        userPromise = db.adaptor.findByGoogleId(oAuthUserId);
        break;
      case 'facebook':
        userPromise = db.adaptor.findByFacebookId(oAuthUserId);
        break;
    }

    if (!userPromise) {
      var unknownOAuthProviderError = new errors.UnknownOAuthProviderError(null, oAuthProvider);
      req.log.error(unknownOAuthProviderError);
      return done(unknownOAuthProviderError);
    }

    userPromise.then(function(user) {
      if (user) {
        req.log = req.log.child({
          user: user.id
        });

        req.log.info('Successfully authenticated user');
        done(null, user);
      } else {
        req.log.info('Could not find user by oauth user id');
        done();
      }
    }).catch(function(err) {
      req.log.error(err);
      done(err);
    });
  };
}

function validatePayloadForUser(user, jwtPayload) {
  if (jwtPayload) {
    var lastLogout = db.adaptor.getLastLogout(user);

    // iat is in seconds
    if (lastLogout && Math.floor(lastLogout / 1000) >= jwtPayload.iat) {
      return Promise.reject(
        new errors.LogoutExpiredJWTError(null, user._id)
      );
    } else {
      return Promise.resolve(); // can't be invalid if hasn't logout yet
    }
  }

  return Promise.reject(
    new errors.InvalidJWTPayloadError(null, user._id, jwtPayload)
  );
}

function createLocalStrategy(options) {
  return new LocalStrategy({
    usernameField: options.usernameProperty,
    passwordField: options.passwordProperty,
    passReqToCallback: true
  }, localAuthenticate(options));
}

function createJWTStrategy(options) {
  return new JwtStrategy({
    secretOrKey: options.secretOrKey,
    passReqToCallback: true
  }, jwtAuthenticate(options));
}

function createOAuthAccessTokenStrategy(options) {
  return new OAuthAccessTokenStrategy({
    googleClientId: options.googleClientId,
    facebookClientId: options.facebookClientId,
    facebookClientSecret: options.facebookClientSecret,
    passReqToCallback: true
  }, oAuthAccessTokenAuthenticate(options));
}

function getAuthenticator(strategy) {
  return passport.authenticate(strategy, {
    session: false
  });
}

function getHashAndSaltForPassword(password, options) {
  return new Promise(function(resolve, reject) {
    crypto.randomBytes(options.saltLength, function(err, buf) {
      if (err) {
        return reject(err);
      }

      var salt = buf.toString(options.encoding);

      crypto.pbkdf2(password, salt, options.pbkdf2Iterations, options.pbkdf2KeyLength, options.pbkdf2Algorithm, function(err, hashRaw) {
        if (err) {
          return reject(err);
        }

        return resolve({
          hash: new Buffer(hashRaw, 'binary').toString(options.encoding),
          salt: salt
        });
      });
    });
  });
}

function maybeSaveLoginAttempt(user, options, contextLog) {
  if (hasLoginAttemptLimit(options)) {
    var newAttempts = db.adaptor.getLoginAttempts(user) + 1;
    var changes = {
      loginAttempts: newAttempts
    };

    if (isLoginAttemptLocked(user, newAttempts, options)) {
      changes.loginAttemptLockTime = Date.now();
    } else if (db.adaptor.getLoginAttemptLockTime(user)) {
      // if not locked but still has a value for lock time, reset it
      changes.loginAttempts = 1;
      changes.loginAttemptLockTime = null;
    }

    return db.adaptor.update(user, changes).catch(function(err) {
      contextLog.error(err);
      return Promise.reject(err);
    });
  } else {
    return Promise.resolve();
  }
}

/////////////////////////
//        INIT         //
/////////////////////////

function init(app, options) {
  app.use(passport.initialize());
  passport.use(createLocalStrategy(options));
  passport.use(createJWTStrategy(options));
  passport.use(createOAuthAccessTokenStrategy(options));
}

///////////////////////////
//        PUBLIC         //
///////////////////////////

exports = module.exports = init;

exports.authenticate = authenticate;
exports.generateToken = generateToken;
exports.getHashAndSaltForPassword = getHashAndSaltForPassword;
exports.generateResetPasswordToken = generateResetPasswordToken;
exports.getResetPasswordHashForToken = getResetPasswordHashForToken;