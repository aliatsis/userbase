var validateMessageAdaptor = require('./validators/validateMessageAdaptor');

function init(messageAdaptor) {
  validateMessageAdaptor(messageAdaptor);
  exports.adaptor = messageAdaptor;
}

exports = module.exports = init;