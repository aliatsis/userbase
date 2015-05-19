var Promise = require("es6-promise").Promise;
var extend = require('extend');
var log = require('bunyan').createLogger({
    name: 'user: UserController'
});

var AuthController = require('./AuthController');
var db = require('../db');

///////////////////////////
//        HELPERS        //
///////////////////////////

function getProfile(options, req, res) {
    res.json(db.get().getProfile(req.user));
}

function login(options, req, res) {
    res.json(AuthController.serializeWithToken(req.user, options));
}

function logout(options, req, res) {
    db.get().update(req.user, {
        lastLogout: Date.now()
    }).then(function() {
        req.logout();

        res.json({
            "message": "User has successfully logged out!"
        });
    }, function() {
        res.json({
            "message": "Failed to log user out!"
        });
    })
}

function saveNewUser(bodyProps, options) {
    var password = bodyProps[options.passwordProperty];

    return AuthController.getHashAndSaltForPassword(password, options).then(function(hashAndSalt) {
        var props = extend({}, bodyProps, hashAndSalt); // make copy to be safe

        return db.get().create(props);
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

    db.get().findByUsername(username).then(function(existingUser) {
        if (existingUser) {
            return next(new Error('ExistingUserError: a user already exists with the ' + options.usernameProperty + ' ' + username));
        }

        saveNewUser(req.body, options).then(function(newUser) {
            log.info('Signed Up User:', username);
            res.json(
                AuthController.serializeWithToken(newUser, options)
            );
        }, function(err) {
            log.error('Error saving new user during signup:', username, err);
            return next(err);
        });

    }, function(err) {
        log.error('Error regeristing User:', username, err);
        return next(err);
    });
}

/////////////////////////
//        INIT         //
/////////////////////////

function init(dbAdaptor) {

}

///////////////////////////
//        PUBLIC         //
///////////////////////////

module.exports = {
    init: init,
    getProfile: getProfile,
    login: login,
    logout: logout,
    signup: signup
};