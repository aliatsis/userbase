var express = require('express');
var morgan = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var methodOverride = require('method-override');
var extend = require('extend');
var domain = require('domain');

var log = require('./logger')('server');
var db = require('./db');
var messenger = require('./messenger');
var AuthController = require('./controllers/AuthController');
var router = require('./router');
var defaultOptions = require('./defaultOptions');
var emitter = require('./emitter');
var userbaseDomain = domain.create();

/////////////////////////
//        INIT         //
/////////////////////////

userbaseDomain.on('error', function(err) {
  log.fatal(err);
  process.exit(1);
});

morgan.token('user', function getId(req) {
  return req.user && req.user._id || '';
});

function init(app, options) {
  var morganFormat = morgan.combined.replace(':status', ':status :user');

  if (process.env.NODE_ENV === 'development') {
    morganFormat = 'dev';
  }

  app.use(morgan(morganFormat));

  app.use(bodyParser.json());
  app.use(bodyParser.urlencoded({
    extended: false
  }));
  app.use(methodOverride());
  app.use(cookieParser());

  // configure athentication middleware
  AuthController(app, options);
}

function registerDbAdaptor(app, options, dbAdaptor) {
  return db(dbAdaptor).then(function() {
    // register api routes on successful db connection
    router(app, options);
    log.info('Registered API routes');

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
  exports.emitter = emitter;
  exports.apiEnvelope = options.apiEnvelope;

  return app;
}

///////////////////////////
//        EXPORTS        //
///////////////////////////

exports = module.exports = userbaseDomain.bind(createUserbaseApp);