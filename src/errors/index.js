var util = require('util');

var errorNameToDefaultMessage = {
  UnknownUsernameError: 'No user was found with username: %s',
  UnknownJWTSubjectError: 'No user was found with id: %s',
  InvalidJWTPayloadError: 'JWT payload is invalid. user: %s; payload: %j',
  LogoutExpiredJWTError: 'JWT has expired due to user logout post iat. user: %s',
  InvalidCredentialsError: 'Incorrect username and password combination',
  LockedAccountError: 'User account has been locked due to excessive failed authentication attempts',
  NoSaltError: 'User does not have a salt stored.'
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