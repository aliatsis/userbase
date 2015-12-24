var UserController = require('../controllers/UserController');
var OAuthController = require('../controllers/OAuthController');

module.exports = function(options, router) {
  router = router || require('express').Router();

  router.route(options.routes.login).post(UserController.login.bind(null, options));
  router.route(options.routes.loginOAuth).post(UserController.login.bind(null, options));
  router.route(options.routes.logout).post(UserController.logout.bind(null, options));
  router.route(options.routes.signup).post(UserController.signup.bind(null, options));
  router.route(options.routes.forgotPassword).post(UserController.forgotPassword.bind(null, options));
  router.route(options.routes.resetPassword + '/:token').post(UserController.resetPassword.bind(null, options));
  router.route(options.routes.profile)
    .get(UserController.getProfile.bind(null, options))
    .put(UserController.updateProfile.bind(null, options));
  router.route(options.routes.oAuthProfile).post(OAuthController.getOAuthProfile.bind(null, options));

  return router;
};