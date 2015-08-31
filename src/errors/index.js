var util = require('util');

var errorNameToDefaultMessage = {
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
  ExistingUserError: 'A user already exists with that %s',
  InvalidResetPasswordTokenError: 'Reset password token is invalid',
  ExpiredResetPasswordTokenError: 'Reset password token is expired'
};

Object.keys(errorNameToDefaultMessage).forEach(function(errorName) {
  var defaultMessage = errorNameToDefaultMessage[errorName];
  module.exports[errorName] = makeError(errorName, defaultMessage);
});

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