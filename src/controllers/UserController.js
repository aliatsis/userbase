var extend = require('extend');
var AuthController = require('./AuthController');
var db = require('../db');
var messenger = require('../messenger');
var emitter = require('../emitter');
var errors = require('../errors');
var sendResponse = require('../sendResponse');

///////////////////////////
//        HELPERS        //
///////////////////////////

function getProfile(options, req, res) {
  req.log.info('Get profile');

  sendResponse(options, req, res, db.adaptor.getProfile(req.user));
}

function updateProfile(options, req, res, next) {
  req.log.info('Updating profile');

  db.adaptor.updateProfile(req.user, req.body).then(function(user) {
    req.log.info('Updated profile');
    sendResponse(options, req, res, db.adaptor.getProfile(user));
  }).catch(next);
}

function login(options, req, res, next) {
  req.log.info('Logging in');

  AuthController.generateToken(req, res, options).then(function(token) {
    req.log.info('Emitting login event');
    emitter.once('login', function(rq, rs, data) {
      req.log.info('Received login event');
      sendResponse(options, rq, rs, data);
    }).emit('login', req, res, token);
  }).catch(next);
}

function logout(options, req, res, next) {
  req.log.info('Logging out');

  db.adaptor.update(req.user, {
    lastLogout: Date.now()
  }).then(function() {
    req.logout();
    req.log.info('Logged out');
    sendResponse(options, req, res);
  }).catch(next);
}

function getPasswordProps(req, options) {
  var password = req.body[options.passwordProperty];

  if (password) {
    return AuthController.getHashAndSaltForPassword(password, options);
  } else {
    return Promise.resolve({});
  }
}

function saveNewUser(req, options) {
  return getPasswordProps(req, options).then(function(passwordProps) {
    var props = extend({
      signupDate: Date.now()
    }, req.body, passwordProps); // make copy to be safe

    return db.adaptor.create(props);
  });
}

function signup(options, req, res, next) {
  var username = req.body[options.usernameProperty];
  var password = req.body[options.passwordProperty];

  if (!username) {
    var missingUsernameErr = new errors.MissingUsernameError(null, options.usernameProperty);
    return sendResponse(options, req, res, null, missingUsernameErr);
  }

  if (!password && requirePasswordForSignupRequest(req, options)) {
    var missingPasswordErr = new errors.MissingPasswordError(null, options.passwordProperty);
    return sendResponse(options, req, res, null, missingPasswordErr);
  }

  if (!password && !requestHasOAuth(req, options)) {
    var invalidSignupRequestError = new errors.InvalidSignupRequestError();
    return sendResponse(options, req, res, null, invalidSignupRequestError);
  }

  req.log = req.log.child({
    username: username
  });

  req.log.info('Signing up user');

  db.adaptor.findByUsername(username).then(function(existingUser) {
    if (existingUser) {
      var exisingUserErr = new errors.ExistingUserError(null, options.usernameProperty);
      return sendResponse(options, req, res, null, exisingUserErr);
    } else {
      return saveNewUser(req, options).then(function(newUser) {
        req.log = req.log.child({
          username: '', // clear username association with user id in logs
          user: newUser._id
        });

        req.log.info('Signed up user');
        req.user = newUser;

        return AuthController.generateToken(req, res, options);
      }).then(function(token) {
        req.log.info('Emitting signup event');
        emitter.once('signup', function(rq, rs, data) {
          req.log.info('Received signup event');
          sendResponse(options, rq, rs, data);
        }).emit('signup', req, res, token);
      });
    }
  }).catch(next);
}

function requirePasswordForSignupRequest(req, options) {
  var hasOAuth = requestHasOAuth(req, options);
  return !hasOAuth || (hasOAuth && options.requirePasswordForOAuthSignup);
}

function requestHasOAuth(req, options) {
  return !!(req.body[options.googleIdProperty] || req.body[options.facebookIdProperty]);
}

function sendResetPasswordLink(req, user, options) {
  req.log.info('Generating reset password token');
  return AuthController.generateResetPasswordToken(user, options).then(function(token) {
    req.log.info('Sending reset password link');
    return messenger.adaptor.sendResetPasswordLink(user, token);
  });
}

function forgotPassword(options, req, res, next) {
  var username = req.body[options.usernameProperty];
  var email = req.body[options.emailProperty];

  if (!username || !email) {
    return sendResponse(options, req, res, null, new errors.MissingRequestPropertyError(
      null, 'username or email', options.usernameProperty + ' or ' + options.emailProperty
    ));
  }

  req.log = req.log.child({
    username: username || '',
    email: email || ''
  });

  req.log.info('Forgot password');

  var userPromise = username ? db.adaptor.findByUsername(username) : db.adaptor.findByEmail(email);

  userPromise.then(function(user) {
    if (user) {
      req.log = req.log.child({
        username: '', // clear username association with user id in logs
        email: '', // clear email association with user id in logs
        user: user._id
      });

      return sendResetPasswordLink(req, user, options).then(function() {
        req.log.info('Successfully sent reset password token');
        sendResponse(options, req, res);
      }).catch(next);
    } else {
      var unknownUserErr = new errors.UnknownUserError(null, username || email);
      return sendResponse(options, req, res, null, unknownUserErr);
    }
  }).catch(next);
}

function resetPassword(options, req, res, next) {
  var password = req.body[options.passwordProperty];

  if (!password) {
    var missingPasswordErr = new errors.MissingPasswordError(null, options.passwordProperty);
    return sendResponse(options, req, res, null, missingPasswordErr);
  }

  req.log.info('Reset Password');

  AuthController.getResetPasswordHashForToken(
    req.params.token, options
  ).then(function(resetPasswordHash) {
    req.log.info('Finding user by reset password hash');
    return db.adaptor.findByResetPasswordHash(resetPasswordHash);
  }).then(function(user) {
    req.user = user;
    req.log = req.log.child({
      user: user._id
    });

    if (!user) {
      var invalidResetTokenErr = new errors.InvalidResetPasswordTokenError();
      return sendResponse(options, req, res, null, invalidResetTokenErr);
    }

    var resetPasswordExpiration = +db.adaptor.getResetPasswordExpiration(user);
    if (Date.now() < resetPasswordExpiration) {
      return getPasswordProps(req, options).then(function(passwordProps) {
        var changes = extend(passwordProps, {
          resetPasswordHash: null,
          resetPasswordExpiration: null
        });

        return db.adaptor.update(req.user, changes);
      }).then(function() {
        req.log.info('Successfully reset password');
        sendResponse(options, req, res);
      });
    } else {
      var expiredResetTokenErr = new errors.ExpiredResetPasswordTokenError();
      return sendResponse(options, req, res, null, expiredResetTokenErr);
    }
  }).catch(next);
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