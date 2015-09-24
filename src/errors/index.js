var util = require('util');

module.exports.add = function() {
  var arg0 = arguments[0];
  if (typeof arg0 === 'string') {
    addOne(arg0, arguments[1]);
  } else if (typeof arg0 === 'object') {
    Object.keys(arg0).forEach(function(errorName) {
      addOne(errorName, arg0[errorName]);
    });
  }
};

(function init() {
  module.exports.add({
    UnknownUserError: 'No user was found for: %s',
    UnknownUsernameError: 'No user was found with username: %s',
    UnknownJWTSubjectError: 'No user was found with id: %s',
    InvalidJWTPayloadError: 'JWT payload is invalid. user: %s; payload: %j',
    LogoutExpiredJWTError: 'JWT has expired due to user logout post iat. user: %s',
    InvalidCredentialsError: 'Incorrect username and password combination',
    LockedAccountError: 'User account has been locked due to excessive failed authentication attempts',
    NoSaltError: 'User does not have a salt stored.',
    MissingRequestPropertyError: 'Missing %s in request property: %s',
    MissingUsernameError: 'Missing username in request property: %s',
    MissingEmailError: 'Missing email in request property: %s',
    MissingPasswordError: 'Missing password in request property: %s',
    MissingGoogleClientIdError: 'Missing googleClientId for Google OAuth 2.0 authentication',
    MissingGoogleClientSecretError: 'Missing googleClientSecret for Google OAuth 2.0 authentication',
    UnknownOAuthProviderError: 'Unknown OAuth provider: %s',
    ExistingUserError: 'A user already exists with that %s',
    InvalidResetPasswordTokenError: 'Reset password token is invalid',
    ExpiredResetPasswordTokenError: 'Reset password token is expired',
    InvalidSignupRequestError: 'The signup request has insufficient data. A password or OAuth user id is required'
  });
})();

function addOne(errorName, defaultMessage) {
  module.exports[errorName] = makeError(errorName, defaultMessage);
}

function makeError(name, defaultMessage) {
  var errorFn = function(message) {
    var trailingArgs = Array.prototype.slice.call(arguments, 1);

    this.name = name;
    this.message = util.format.apply(util, [message || defaultMessage].concat(trailingArgs));
    this.stack = (new Error()).stack;
  };

  errorFn.prototype = Object.create(Error.prototype);
  errorFn.prototype.constructor = errorFn;

  return errorFn;
}