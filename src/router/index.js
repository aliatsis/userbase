var AuthController = require('../controllers/AuthController');
var UserRouter = require('./UserRouter');

///////////////////////////
//        HELPERS        //
///////////////////////////

function addAuthenticatedRouter(app, options, path, router, unauthenticatePaths) {
    app.use(options.basePath + path, AuthController.authenticate(unauthenticatePaths, options), router);
}

/////////////////////////
//        INIT         //
/////////////////////////

function init(app, options) {
    var SIGNUP_PATH = options.basePath + options.userPath + options.routes.signup;
    var FORGOT_PASSWORD_PATH = options.basePath + options.userPath + options.routes.forgotPassword;
    var RESET_PASSWORD_PATH = new RegExp(options.basePath + options.userPath + options.routes.resetPassword + '/[a-zA-Z0-9]+$');
    var UNAUTHENTICATED_PATHS = [SIGNUP_PATH, FORGOT_PASSWORD_PATH, RESET_PASSWORD_PATH];

    try {
        addAuthenticatedRouter(app, options, options.userPath, UserRouter(options), UNAUTHENTICATED_PATHS);
    } catch (e) {
        console.error(e);
    }
}

///////////////////////////
//        PUBLIC         //
///////////////////////////

exports = module.exports = init;

exports.addAuthenticatedRouter = addAuthenticatedRouter;