var express = require('express');
var morgan = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var methodOverride = require('method-override');
var ipaddr = require('ipaddr.js');
var extend = require('extend');
var domain = require('domain');
var VError = require('verror');

var log = require('./logger')('server');
var db = require('./db');
var messenger = require('./messenger');
var AuthController = require('./controllers/AuthController');
var router = require('./router');
var defaultOptions = require('./defaultOptions');
var emitter = require('./emitter');
var errors = require('./errors');

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

  if (options.ipv4) {
    addIPv4Middleware(app);
  }

  // configure athentication middleware
  AuthController(app, options);

  process.nextTick(function() {
    // error handler configuration after routers are synchronously registered
    addErrorMiddleware(app, options);
  });
}

function registerDbAdaptor(app, options, dbAdaptor) {
  return db(dbAdaptor).then(function() {
    app.listen(options.port);
    log.info('App listening on port', options.port);
  });
}

function registerMessageAdaptor(app, options, messageAdaptor) {
  return messenger(messageAdaptor);
}

function addIPv4Middleware(app) {
  app.use(function(req, res, next) {
    var ip = req.ip;

    Object.defineProperty(req, 'ip', {
      get: function() {
        return ip;
      },
      set: function(val) {
        ip = ipaddr.process(val).toString();
      }
    });

    req.ip = req.ip;
    next();
  });
}

function addErrorMiddleware(app, options) {
  // catch 404 and forward to error handler
  app.use(function(req, res, next) {
    var err = new VError('Not Found: ' + req.url);
    err.status = 404;
    next(err);
  });

  app.use(function(err, req, res, next) {
    (req.log || log).error(err);

    if (res.headersSent) {
      return next(err);
    }

    var data = options.apiEnvelope(null, err);

    // request library uses statucCode
    res.status(err.status || err.statusCode || 500).send(data);
  });
}

function createUserbaseApp(options) {
  var app = express();
  options = extend(true, defaultOptions, options);

  init(app, options);

  exports.router = router(app, options);
  exports.registerDbAdaptor = registerDbAdaptor.bind(this, app, options);
  exports.registerMessageAdaptor = registerMessageAdaptor.bind(this, app, options);
  exports.apiEnvelope = options.apiEnvelope;

  return app;
}

///////////////////////////
//        EXPORTS        //
///////////////////////////

exports = module.exports = userbaseDomain.bind(createUserbaseApp);

exports.emitter = emitter;
exports.errors = errors;