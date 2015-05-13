var log = require('bunyan').createLogger({
    name: 'user: db'
});

var validateDbAdaptor = require('./validators/validateDbAdaptor');
var validatePromise = require('./validators/validatePromise');

var adaptor;

////////////////////////////
//        HELPERS         //
////////////////////////////

function connect(dbAdaptor) {
    validateDbAdaptor(dbAdaptor);

    log.info('Attempting to connect to database');

    var dbConnectPromise = validatePromise(dbAdaptor.connect(), 'connect() function of database adaptor');
    adaptor = dbAdaptor;

    return dbConnectPromise.then(function() {
        log.info('Successfully connected to database');
    });
}

function get() {
    if (adaptor) {
        return adaptor;
    } else {
        throw new Error('Database adaptor has not been initialized. Wait for connect() promise to be fulfilled.');
    }
}

///////////////////////////
//        PUBLIC         //
///////////////////////////

module.exports = {
    connect: connect,
    get: get
};