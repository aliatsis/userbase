var port = process.env.PORT || 8080;
var userPath = '/user';

module.exports = {
  port: port,
  basePath: '',
  userPath: userPath,
  routes: {
    login: '/login',
    loginOAuth: '/login/oauth',
    logout: '/logout',
    signup: '/signup',
    profile: '/profile',
    oAuthProfile: '/profile/oauth',
    forgotPassword: '/forgotPassword',
    resetPassword: '/resetPassword'
  },
  usernameProperty: 'username',
  passwordProperty: 'password',
  emailProperty: 'email',
  googleIdProperty: 'googleId',
  facebookIdProperty: 'facebookId',
  loginAttemptLimit: 5,
  loginAttemptLockDuration: 15, // minutes
  pbkdf2Iterations: 25000,
  pbkdf2KeyLength: 512,
  pbkdf2Algorithm: 'sha512',
  saltLength: 32,
  encoding: 'hex',
  tokenExpiresInSeconds: 0, // fall through to minutes
  tokenExpiresInMinutes: 30,
  resetPasswordTokenLength: 32,
  resetPasswordExpiration: 15, // minutes
  apiEnvelope: function(data, error, req, res) {
    if (data instanceof Error) {
      error = data;
      data = null;
    }

    var result = {
      result: data
    };

    if (error) {
      result.error = {
        name: error instanceof Error ? error.name : 'Error',
        message: error instanceof Error ? error.message : error
      };
    }

    return result;
  },
  secretOrKey: 'secret',
  requirePasswordForOAuthSignup: false,
  facebookProfileFields: ''
};