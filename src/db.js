var log = require('bunyan').createLogger({
    name: 'userbase: db'
});

var validateDbAdaptor = require('./validators/validateDbAdaptor');
var validatePromise = require('./validators/validatePromise');

////////////////////////////
//        HELPERS         //
////////////////////////////

function connect(dbAdaptor) {
    validateDbAdaptor(dbAdaptor);

    log.info('Attempting to connect to database');

    var dbConnectPromise = validatePromise(dbAdaptor.connect(), 'connect() function of database adaptor');
    exports.adaptor = dbAdaptor;

    return dbConnectPromise.then(function() {
        log.info('Successfully connected to database');
    });
}

///////////////////////////
//        PUBLIC         //
///////////////////////////

exports = module.exports = connect;