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

function getUser(options, req, res) {
    res.json(req.user);
}

function login(options, req, res) {
    // login authentication populates req.user with { token: XXX, user: { }}
    res.json(req.user);
}

function logout(options, req, res) {
    req.logout();

    db.get().update({
        lastLogout: Data.now()
    });

    res.json({
        "message": "User has successfully logged out!"
    });
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
    getUser: getUser,
    login: login,
    logout: logout,
    signup: signup
};