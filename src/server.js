var express = require('express');
var logger = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var methodOverride = require('method-override');
var errorMiddleware = require('ajl-express-error-middleware');
var extend = require('extend');
var log = require('bunyan').createLogger({
    name: 'user: server'
});

var db = require('./db');
var AuthController = require('./controllers/AuthController');
var router = require('./router');
var defaultOptions = require('./defaultOptions');

/////////////////////////
//        INIT         //
/////////////////////////

function init(app, dbAdaptor, options) {
    app.use(logger('dev'));
    app.use(bodyParser.json());
    app.use(bodyParser.urlencoded({
        extended: false
    }));
    app.use(methodOverride());
    app.use(cookieParser());

    // configure athentication middleware
    AuthController.init(app, options);

    // connect to db
    db.connect(dbAdaptor).then(function() {
        // register api routes on successful db connection
        router.init(app, options);
        log.info('Registered API routes');

        // error handler configuration after routers are registered
        errorMiddleware(app);
    });

    app.listen(options.port);
    log.info('App listening on port', options.port);
}

///////////////////////////
//        EXPORTS        //
///////////////////////////

module.exports = function(dbAdaptor, options) {
    options = extend(true, defaultOptions, options);
    app = express();

    process.nextTick(init.bind(null, app, dbAdaptor, options));

    return {
        app: app,
        addAuthenticatedRouter: router.addAuthenticatedRouter.bind(this, app, options)
    };
};