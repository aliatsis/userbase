var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var JwtStrategy = require('passport-jwt').Strategy;
var GoogleStrategy = require('passport-google-oauth').OAuth2Strategy;
var Promise = require('es6-promise').Promise;
var unless = require('express-unless');
var crypto = require('crypto');
var jwt = require('jsonwebtoken');
var scmp = require('scmp');
var extend = require('extend');

var emitter = require('../emitter');
var errors = require('../errors');
var db = require('../db');

///////////////////////////
//        HELPERS        //
///////////////////////////

function authenticate(ignoredPaths, options) {
  var middleware = function(req) {
    var authenticator;

    // use local strategy for login request
    if (~req.url.indexOf(options.routes.login)) {
      authenticator = getAuthenticator('local');
    } else if (~req.url.indexOf(options.routes.googleOAuth) || ~req.url.indexOf(options.routes.googleOAuthCallback)) {
      authenticator = getAuthenticator('google', {
        scope: options.googleScope
      });
    } else {
      authenticator = getAuthenticator('jwt');
    }

    authenticator.apply(this, arguments);
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

function googleAuthenticate(options) {
  return function(req, accessToken, refreshToken, profile, done) {
    var googleId = profile && profile.id;

    req.log = req.log.child({
      googleId: googleId,
      strategy: 'google'
    });

    db.adaptor.findByGoogleProfile(profile).then(function(user) {
      if (user) {
        req.log = req.log.child({
          user: user.id
        });

        req.log.info('Successfully authenticated user');
        done(null, user);
      } else {
        var unknownGoogleUserError = new errors.UnknownGoogleUserError(null, googleId);
        req.log.info('Could not find user with google profile');

        // pass UnknownGoogleUserError as the use so the authenticated route can know what to do
        done(null, profile);
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

function createGoogleStrategy(options) {
  if (!options.googleClientId) {
    throw new errors.MissingGoogleClientIdError();
  }

  if (!options.googleClientSecret) {
    throw new errors.MissingGoogleClientSecretError();
  }

  return new GoogleStrategy({
    clientID: options.googleClientId,
    clientSecret: options.googleClientSecret,
    callbackURL: options.googleCallbackURL,
    passReqToCallback: true
  }, googleAuthenticate(options));
}

function getAuthenticator(strategy, strategyOptions) {
  return passport.authenticate(strategy, extend(strategyOptions, {
    session: false
  }));
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

  if (options.googleOAuth) {
    passport.use(createGoogleStrategy(options));
  }
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