var router = require('express').Router();
var UserController = require('../controllers/UserController');

module.exports = function(options) {
  router.route(options.routes.login).post(UserController.login.bind(null, options));
  router.route(options.routes.logout).post(UserController.logout.bind(null, options));
  router.route(options.routes.signup).post(UserController.signup.bind(null, options));
  router.route(options.routes.forgotPassword).post(UserController.forgotPassword.bind(null, options));
  router.route(options.routes.resetPassword + '/:token').post(UserController.resetPassword.bind(null, options));
  router.route(options.routes.profile)
    .get(UserController.getProfile.bind(null, options))
    .put(UserController.updateProfile.bind(null, options));

  //OAuth routes
  router.route(options.routes.googleOAuth).all(function(req, res, next) {
    next();
  });
  router.route(options.routes.googleOAuthCallback).all(function(req, res, next) {
    next();
  });

  return router;
};