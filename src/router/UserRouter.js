var router = require('express').Router();
var UserController = require('../controllers/UserController');

module.exports = function(options) {
    var userRoute = options.routes.user ? router.route(options.routes.user) : router;
    userRoute.get(UserController.getUser.bind(null, options));

    router.route(options.routes.login).post(UserController.login.bind(null, options));
    router.route(options.routes.logout).post(UserController.logout.bind(null, options));
    router.route(options.routes.signup).post(UserController.signup.bind(null, options));

    return router;
};