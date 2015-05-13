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

    try {
        addAuthenticatedRouter(app, options, options.userPath, UserRouter(options), SIGNUP_PATH);
    } catch (e) {
        console.error(e);
    }
}

///////////////////////////
//        PUBLIC         //
///////////////////////////

module.exports = {
    init: init,
    addAuthenticatedRouter: addAuthenticatedRouter
};