var bunyan = require('bunyan');
var PrettyStream = require('bunyan-prettystream');

var prettyStdOut = new PrettyStream();
prettyStdOut.pipe(process.stdout);

module.exports = function(name) {
  var logOptions = {
    name: 'userbase: ' + name
  };

  if (process.env.NODE_ENV === 'development') {
    logOptions.streams = [{
      level: 'debug',
      type: 'raw',
      stream: prettyStdOut
    }];
  }

  return bunyan.createLogger(logOptions);
};