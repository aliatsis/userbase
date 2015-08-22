var extend = require('extend');
var log = require('bunyan').createLogger({
    name: 'userbase: UserController'
});

var AuthController = require('./AuthController');
var db = require('../db');
var messenger = require('../messenger');
var emitter = require('../emitter');

///////////////////////////
//        HELPERS        //
///////////////////////////

function sendResponse(options, req, res, data) {
    if (typeof options.apiEnvelope === 'function') {
        data = options.apiEnvelope(req, res, data);
    }

    res.json(data);
}

function getProfile(options, req, res) {
    sendResponse(options, req, res, db.adaptor.getProfile(req.user));
}

function updateProfile(options, req, res, next) {
    db.adaptor.updateProfile(req.user, req.body).then(function(user) {
        sendResponse(options, req, res, db.adaptor.getProfile(user));
    }, function(err) {
        return next(err);
    });
}

function login(options, req, res) {
    AuthController.generateToken(req, res, options).then(function(token) {
        emitter.on('login', function(rq, rs, data) {
            sendResponse(options, rq, rs, data);
        }).emit('login', req, res, token);
    });
}

function logout(options, req, res, next) {
    db.adaptor.update(req.user, {
        lastLogout: Date.now()
    }).then(function() {
        req.logout();
        sendResponse(options, req, res, 'User has successfully logged out!');
    }, function(err) {
        return next(err);
    });
}

function getPasswordProps(req, options) {
    return AuthController.getHashAndSaltForPassword(req.body[options.passwordProperty], options);
}

function saveNewUser(req, options) {
    return getPasswordProps(req, options).then(function(passwordProps) {
        var props = extend({}, req.body, passwordProps); // make copy to be safe

        return db.adaptor.create(props);
    });
}

function signup(options, req, res, next) {
    var username = req.body[options.usernameProperty];
    var password = req.body[options.passwordProperty];

    if (!username) {
        return next(new Error('MissingUsernameError: signup missing username in request property ' + options.usernameProperty));
    }

    if (!password) {
        return next(new Error('MissingPasswordError: signup missing password in request property ' + options.passwordProperty));
    }

    log.info('Signing Up User:', username);

    db.adaptor.findByUsername(username).then(function(existingUser) {
        if (existingUser) {
            return next(new Error('ExistingUserError: a user already exists with the ' + options.usernameProperty + ' ' + username));
        }

        saveNewUser(req, options).then(function(newUser) {
            log.info('Signed Up User:', username);
            req.user = newUser;

            return AuthController.generateToken(req, res, options);
        }).then(function(token) {
            emitter.on('signup', function(rq, rs, data) {
                sendResponse(options, rq, rs, data);
            }).emit('signup', req, res, token);
        }, function(err) {
            log.error('Error saving new user during signup:', username, err);
            return next(err);
        });

    }, function(err) {
        log.error('Error regeristing User:', username, err);
        return next(err);
    });
}

function sendResetPasswordLink(user, options) {
    var userId = db.adaptor.getId(user);
    log.info('Generating reset password token for user:', userId);
    return AuthController.generateResetPasswordToken(user, options).then(function(token) {
        log.info('Sending reset password link for user:', userId);
        return messenger.adaptor.sendResetPasswordLink(user, token);
    }).then(function() {
        log.info('Successfully sent reset password token for user:', userId);
    }).catch(console.log.bind(console));
}

function forgotPassword(options, req, res, next) {
    var username = req.body[options.usernameProperty];
    var email = req.body[options.emailProperty];

    if (!username || !email) {
        return next(new Error('MissingUsernameOrEmailError: forgot password is missing a username or email in request property'));
    }

    var userPromise = username ? db.adaptor.findByUsername(username) : db.adaptor.findByEmail(email);

    userPromise.then(function(user) {
        if (user) {
            return sendResetPasswordLink(user, options).then(function() {
                sendResponse(options, req, res, 'Successfully sent password reset link to user!');
            }).catch(function(err) {
                console.log(err);
                return next(err);
            });
        } else {
            return next(null, false, {
                message: 'UserDoesNotExistError'
            });
        }
    }).catch(function(err) {
        log.error('Error finding user for forgot password:', username || email, err);
        return next(err);
    });
}

function resetPassword(options, req, res, next) {
    var password = req.body[options.passwordProperty];

    if (!password) {
        return next(new Error('MissingPasswordError: resetPassword missing password in request property ' + options.passwordProperty));
    }

    AuthController.getResetPasswordHashForToken(
        req.params.token, options
    ).then(function(resetPasswordHash) {
        return db.adaptor.findByResetPasswordHash(resetPasswordHash);
    }).then(function(user) {
        if (!user) {
            return next(new Error('ExpiredResetPasswordTokenError'));
        }

        var resetPasswordExpiration = +db.adaptor.getResetPasswordExpiration(user);
        if (Date.now() < resetPasswordExpiration) {
            return getPasswordProps(req, options).then(function(passwordProps) {
                var changes = extend(passwordProps, {
                    resetPasswordHash: null,
                    resetPasswordExpiration: null
                });

                return db.adaptor.update(user, changes).then(function() {
                    sendResponse(options, req, res, 'Successfully reset password!');
                });
            });
        } else {
            return next(new Error('ExpiredResetPasswordTokenError'));
        }
    }).catch(function(err) {
        console.log(err);
        return next(err);
    });
}

///////////////////////////
//        PUBLIC         //
///////////////////////////

module.exports = {
    getProfile: getProfile,
    updateProfile: updateProfile,
    login: login,
    logout: logout,
    signup: signup,
    forgotPassword: forgotPassword,
    resetPassword: resetPassword
};