var AuthController = require('../controllers/AuthController');
var UserRouter = require('./UserRouter');

///////////////////////////
//        HELPERS        //
///////////////////////////

function addAuthenticatedRouter(app, options, path, router, unauthenticatePaths) {
    if (path === options.userPath) {
        var defaultUnauthenticatedUserPaths = getUnauthenticatedUserPaths(options);

        if (!unauthenticatePaths) {
            unauthenticatePaths = defaultUnauthenticatedUserPaths;
        } else if (typeof unauthenticatePaths === 'array') {
            unauthenticatePaths = unauthenticatePaths.concat(defaultUnauthenticatedUserPaths);
        } else if (typeof unauthenticatePaths === 'string') {
            unauthenticatePaths = [unauthenticatePaths].concat(defaultUnauthenticatedUserPaths);
        }
    }

    app.use(options.basePath + path, AuthController.authenticate(unauthenticatePaths, options), router);
}

/////////////////////////
//        INIT         //
/////////////////////////

function init(app, options) {
    try {
        addAuthenticatedRouter(app, options, options.userPath, UserRouter(options), getUnauthenticatedUserPaths(options));
    } catch (e) {
        console.error(e);
    }
}

function getUnauthenticatedUserPaths(options) {
    var SIGNUP_PATH = options.basePath + options.userPath + options.routes.signup;
    var RESET_PASSWORD_PATH = new RegExp(options.basePath + options.userPath + options.routes.resetPassword + '/[a-zA-Z0-9]+$');
    return [SIGNUP_PATH, RESET_PASSWORD_PATH];
}

///////////////////////////
//        PUBLIC         //
///////////////////////////

exports = module.exports = init;

exports.addAuthenticatedRouter = addAuthenticatedRouter;