var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var JwtStrategy = require('passport-jwt').Strategy;
var Promise = require("es6-promise").Promise;
var unless = require('express-unless');
var crypto = require('crypto');
var jwt = require('jsonwebtoken');
var scmp = require('scmp');

var db = require('../db');

var localAuthenticator;
var jwtAuthenticator;

///////////////////////////
//        HELPERS        //
///////////////////////////

function authenticate(ignoredPaths, options) {
    var middleware = function(req, res) {
        var authenticator = jwtAuthenticator;

        // use local strategy for login request
        if (req.url.indexOf(options.routes.login) > -1) {
            authenticator = localAuthenticator;
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
        var loginAttemptLockTime = db.get().getLoginAttemptLockTime(user);

        if (loginAttemptLockTime) {
            var ms = options.loginAttemptLockDuration * 60000;

            // should not be considered locked if it's past the lock duration
            return Date.now() < loginAttemptLockTime + ms;
        }

        return loginAttempts >= options.loginAttemptLimit;
    }

    return false;
}

function generateToken(user, options) {
    return jwt.sign({}, options.secretOrKey, {
        subject: db.get().getId(user),
        expiresInSeconds: options.tokenExpiresInSeconds,
        expiresInMinutes: options.tokenExpiresInMinutes
    });
}

function serializeWithToken(user, options) {
    return {
        token: generateToken(user, options),
        user: db.get().serialize(user)
    };
}

function authenticatePassword(user, password, options) {
    return new Promise(function(resolve, reject) {

        var salt = db.get().getSalt(user);

        if (!salt) {
            return reject({
                result: false,
                info: {
                    message: 'NoSaltValueStoredError'
                }
            });
        }

        crypto.pbkdf2(password, salt, options.pbkdf2Iterations, options.pbkdf2KeyLength, function(err, hashRaw) {
            if (err) {
                reject({
                    error: err
                });

                return;
            }

            var hash = new Buffer(hashRaw, 'binary').toString(options.encoding);

            if (scmp(hash, db.get().getHash(user))) {
                if (hasLoginAttemptLimit(options)) {
                    db.get().update(user, {
                        loginAttempts: 0,
                        lastLogin: Date.now(),
                        loginAttemptLockTime: null
                    });
                }

                resolve();

                return;
            } else {
                maybeSaveLoginAttempt(user, options);

                reject({
                    result: false,
                    info: {
                        message: 'IncorrectPasswordError'
                    }
                });

                return;
            }
        });
    });
}

function authenticateUser(user, password, options) {
    return new Promise(function(resolve, reject) {
        if (isLoginAttemptLocked(user, db.get().getLoginAttempts(user), options)) {
            maybeSaveLoginAttempt(user, options);

            return reject({
                result: false,
                info: {
                    message: 'LoginAttemptLockedError'
                }
            });
        }

        resolve();
    }).then(
        authenticatePassword.bind(null, user, password, options)
    );
}

function localAuthenticate(options) {
    return function(username, password, done) {
        return db.get().findByUsername(username).then(function(user) {
            if (user) {
                return authenticateUser(user, password, options).then(function() {
                    done(null, serializeWithToken(user, options));
                }, function(reason) {
                    done(reason.error, reason.result, reason.info);
                });
            } else {
                return done(null, false, {
                    message: 'IncorrectUsernameError'
                });
            }
        }, function(err) {
            return done(err);
        });
    };
}

function jwtAuthenticate(options) {
    return function(jwtPayload, done) {
        return db.get().findById(jwtPayload.sub).then(function(user) {
            if (user) {
                done(null, db.get().serialize(user));
            } else {
                done(null, false, {
                    message: 'IncorrectOrDeletedPayloadSubjectError'
                });
            }
        }, function(err) {
            done(err, false);
        });
    };
}

function createLocalStrategy(options) {
    return new LocalStrategy({
        usernameField: options.usernameProperty,
        passwordField: options.passwordProperty
    }, localAuthenticate(options));
}

function createJWTStrategy(options) {
    return new JwtStrategy({
        secretOrKey: options.secretOrKey
    }, jwtAuthenticate(options));
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
                reject(err);
                return;
            }

            var salt = buf.toString(options.encoding);

            crypto.pbkdf2(password, salt, options.pbkdf2Iterations, options.pbkdf2KeyLength, function(err, hashRaw) {
                if (err) {
                    reject(err);
                    return;
                }

                resolve({
                    hash: new Buffer(hashRaw, 'binary').toString(options.encoding),
                    salt: salt
                });
                return;
            });
        });
    });
}

function maybeSaveLoginAttempt(user, options) {
    if (hasLoginAttemptLimit(options)) {
        var newAttempts = db.get().getLoginAttempts(user) + 1;
        var changes = {
            loginAttempts: newAttempts
        };

        if (isLoginAttemptLocked(user, newAttempts, options)) {
            changes.loginAttemptLockTime = Date.now();
        } else if (db.get().getLoginAttemptLockTime(user)) {
            // if not locked but still has a value for lock time, reset it            
            changes.loginAttempts = 1;
            changes.loginAttemptLockTime = null;
        }

        db.get().update(user, changes);
    }
}

/////////////////////////
//        INIT         //
/////////////////////////

function init(app, options) {
    app.use(passport.initialize());
    passport.use(createLocalStrategy(options));
    passport.use(createJWTStrategy(options));

    localAuthenticator = getAuthenticator('local');
    jwtAuthenticator = getAuthenticator('jwt');
}

///////////////////////////
//        PUBLIC         //
///////////////////////////

module.exports = {
    init: init,
    authenticate: authenticate,
    serializeWithToken: serializeWithToken,
    getHashAndSaltForPassword: getHashAndSaltForPassword
};