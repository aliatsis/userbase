var emitter = require('../emitter');

module.exports = function sendResponse(options, req, res, data, error) {
  if (typeof options.apiEnvelope === 'function') {
    data = options.apiEnvelope(data, error, req, res);
  }

  if (error) {
    req.log.warn(error);
  }

  emitter.once('before-send', function(rq, rs, dataToSend) {
    res.json(dataToSend);
  }).emit('before-send', req, res, data, error);
};