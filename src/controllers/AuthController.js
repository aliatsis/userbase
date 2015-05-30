var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var JwtStrategy = require('passport-jwt').Strategy;
var Promise = require("es6-promise").Promise;
var unless = require('express-unless');
var crypto = require('crypto');
var jwt = require('jsonwebtoken');
var scmp = require('scmp');

var db = require('../db');

///////////////////////////
//        HELPERS        //
///////////////////////////

function authenticate(ignoredPaths, options) {
    var middleware = function(req, res) {
        var authenticator;

        // use local strategy for login request
        if (req.url.indexOf(options.routes.login) > -1) {
            authenticator = getAuthenticator('local');
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

function generateToken(user, options) {
    return jwt.sign({}, options.secretOrKey, {
        subject: db.adaptor.getId(user),
        expiresInSeconds: options.tokenExpiresInSeconds,
        expiresInMinutes: options.tokenExpiresInMinutes
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
                db.adaptor.update(user, {
                    resetPasswordHash: resetPasswordHash,
                    resetPasswordExpiration: Date.now() + options.resetPasswordExpiration * 60000
                }).then(function() {
                    return resolve(resetToken);
                }, reject).catch(console.log.bind(console));
            }, reject).catch(console.log.bind(console));
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

function serializeWithToken(user, options) {
    return {
        token: generateToken(user, options),
        user: db.adaptor.serialize(user)
    };
}

function authenticatePassword(user, password, options) {
    return new Promise(function(resolve, reject) {

        var salt = db.adaptor.getSalt(user);

        if (!salt) {
            return reject({
                result: false,
                info: {
                    message: 'NoSaltValueStoredError'
                }
            });
        }

        crypto.pbkdf2(password, salt, options.pbkdf2Iterations, options.pbkdf2KeyLength, options.pbkdf2Algorithm, function(err, hashRaw) {
            if (err) {
                reject({
                    error: err
                });

                return;
            }

            var hash = new Buffer(hashRaw, 'binary').toString(options.encoding);

            if (scmp(hash, db.adaptor.getHash(user))) {
                if (hasLoginAttemptLimit(options)) {
                    db.adaptor.update(user, {
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
        if (isLoginAttemptLocked(user, db.adaptor.getLoginAttempts(user), options)) {
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
        return db.adaptor.findByUsername(username).then(function(user) {
            if (user) {
                return authenticateUser(user, password, options).then(function() {
                    done(null, user);
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
        return db.adaptor.findById(jwtPayload.sub).then(function(user) {
            if (user) {
                if (validatePayloadForUser(user, jwtPayload)) {
                    done(null, user);
                } else {
                    done(null, false, {
                        message: 'LogoutInvalidatedJWTError'
                    });
                }
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

function validatePayloadForUser(user, jwtPayload) {
    if (user && jwtPayload) {
        var lastLogout = db.adaptor.getLastLogout(user);

        if (lastLogout) {
            return lastLogout < jwtPayload.iat;
        } else {
            // can't be invalid if hasn't logout yet
            return true;
        }
    }

    return false;
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

            crypto.pbkdf2(password, salt, options.pbkdf2Iterations, options.pbkdf2KeyLength, options.pbkdf2Algorithm, function(err, hashRaw) {
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

        db.adaptor.update(user, changes);
    }
}

/////////////////////////
//        INIT         //
/////////////////////////

function init(app, options) {
    app.use(passport.initialize());
    passport.use(createLocalStrategy(options));
    passport.use(createJWTStrategy(options));
}

///////////////////////////
//        PUBLIC         //
///////////////////////////

exports = module.exports = init;

exports.authenticate = authenticate;
exports.serializeWithToken = serializeWithToken;
exports.getHashAndSaltForPassword = getHashAndSaltForPassword;
exports.generateResetPasswordToken = generateResetPasswordToken;
exports.getResetPasswordHashForToken = getResetPasswordHashForToken;