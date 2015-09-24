module.exports = function sendResponse(options, req, res, data, error) {
  if (typeof options.apiEnvelope === 'function') {
    data = options.apiEnvelope(data, error, req, res);
  }

  if (error) {
    req.log.warn(error);
  }

  res.json(data);
};