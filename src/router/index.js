var extend = require('extend');
var AuthController = require('../controllers/AuthController');
var UserRouter = require('./UserRouter');
var logger = require('../logger');
var log = logger('router');

///////////////////////////
//        PUBLIC         //
///////////////////////////

module.exports = init;

/////////////////////////
//        INIT         //
/////////////////////////

function init(app, options) {
  return {
    addUserRouter: addUserRouter.bind(this, app, options),
    addRouter: addRouter.bind(this, app, options),
    addAuthenticatedPathRouter: addAuthenticatedPathRouter.bind(this, app, options),
    addAuthenticatedLocalRouter: addAuthenticatedLocalRouter.bind(this, app, options),
    addAuthenticatedOAuthRouter: addAuthenticatedOAuthRouter.bind(this, app, options),
    addAuthenticatedJWTRouter: addAuthenticatedJWTRouter.bind(this, app, options)
  };
}

function addUserRouter(app, options, customRouter, includeDefaultUserRoutes, authStrategyByPath) {
  if (arguments.length === 2) {
    includeDefaultUserRoutes = true;
  }

  var oauthPaths = [
    options.routes.loginOAuth,
    options.routes.oAuthProfile
  ].filter(function(path) {
    return !!path;
  });
  var userRouter = customRouter;

  if (includeDefaultUserRoutes) {
    userRouter = UserRouter(options, customRouter);
  }

  if (userRouter) {
    addAuthenticatedPathRouter(app, options, options.userPath, userRouter, extend({
      local: options.routes.login && [options.routes.login] || [],
      oauth: oauthPaths,
      none: getUnauthenticatedUserPaths(options)
    }, authStrategyByPath));

    log.info('Registered userbase routes');
  }
}


///////////////////////////
//        HELPERS        //
///////////////////////////

function addAuthenticatedPathRouter(app, options, path, router, authStrategyToPathMap) {
  addRouter(app, options, path, router, AuthController.authenticateByPath(options, authStrategyToPathMap));
}

function addAuthenticatedLocalRouter(app, options, path, router, unauthenticatePaths) {
  addRouter(app, options, path, router, AuthController.authenticateLocal(options, unauthenticatePaths));
}

function addAuthenticatedOAuthRouter(app, options, path, router, unauthenticatePaths) {
  addRouter(app, options, path, router, AuthController.authenticateOAuth(options, unauthenticatePaths));
}

function addAuthenticatedJWTRouter(app, options, path, router, unauthenticatePaths) {
  addRouter(app, options, path, router, AuthController.authenticateJWT(options, unauthenticatePaths));
}

function addRouter(app, options, path, router, authenticator) {
  var routerPath = options.basePath + path;

  addLoggerMiddleware(app, path);

  if (authenticator) {
    app.use(routerPath, authenticator, router);
  } else {
    app.use(routerPath, router);
  }
}

function addLoggerMiddleware(app, routerPath) {
  app.use(function(req, res, next) {
    req.log = logger(routerPath + ' router');
    next();
  });
}

function getUnauthenticatedUserPaths(options) {
  var SIGNUP_PATH = options.basePath + options.userPath + options.routes.signup;
  var RESET_PASSWORD_PATH = new RegExp(options.basePath + options.userPath + options.routes.resetPassword + '/[a-zA-Z0-9]+$');

  return [
    SIGNUP_PATH,
    RESET_PASSWORD_PATH
  ];
}