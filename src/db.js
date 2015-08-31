var log = require('./logger')('db');

var validateDbAdaptor = require('./validators/validateDbAdaptor');

////////////////////////////
//        HELPERS         //
////////////////////////////

function connect(dbAdaptor) {
  validateDbAdaptor(dbAdaptor);

  log.info('Attempting to connect to database');

  exports.adaptor = dbAdaptor;

  return dbAdaptor.connect().then(function() {
    log.info('Successfully connected to database');
  }).catch(function(err) {
    log.fatal(err, 'Failed to connect to database');
    process.exit(1);
  });
}

///////////////////////////
//        PUBLIC         //
///////////////////////////

exports = module.exports = connect;