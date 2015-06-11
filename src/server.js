var express = require('express');
var logger = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var methodOverride = require('method-override');
var errorMiddleware = require('ajl-express-error-middleware');
var cors = require('cors');
var extend = require('extend');
var log = require('bunyan').createLogger({
    name: 'userbase: server'
});

var db = require('./db');
var messenger = require('./messenger');
var AuthController = require('./controllers/AuthController');
var router = require('./router');
var defaultOptions = require('./defaultOptions');
var hooks = require('./hooks');

/////////////////////////
//        INIT         //
/////////////////////////

function init(app, options) {
    app.use(logger('dev'));
    app.use(bodyParser.json());
    app.use(bodyParser.urlencoded({
        extended: false
    }));
    app.use(methodOverride());
    app.use(cookieParser());

    if (options.cors) {
        app.use(cors(options.corsOptions));
    }

    // configure athentication middleware
    AuthController(app, options);
}

function registerDbAdaptor(app, options, dbAdaptor) {
    return db(dbAdaptor).then(function() {
        // register api routes on successful db connection
        router(app, options);
        log.info('Registered API routes');

        // error handler configuration after routers are registered
        errorMiddleware(app);

        app.listen(options.port);
        log.info('App listening on port', options.port);
    });
}

function registerMessageAdaptor(app, options, messageAdaptor) {
    return messenger(messageAdaptor);
}

function createUserbaseApp(options) {
    var app = express();
    options = extend(true, defaultOptions, options);

    init(app, options);

    exports.addAuthenticatedRouter = router.addAuthenticatedRouter.bind(this, app, options);
    exports.registerDbAdaptor = registerDbAdaptor.bind(this, app, options);
    exports.registerMessageAdaptor = registerMessageAdaptor.bind(this, app, options);
    exports.hooks = hooks;

    return app;
}

///////////////////////////
//        EXPORTS        //
///////////////////////////

exports = module.exports = createUserbaseApp;