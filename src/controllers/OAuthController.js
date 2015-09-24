var rp = require('request-promise');
var util = require('util');

var sendResponse = require('../sendResponse');

var OAuthController = module.exports;

///////////////////////////
//        PUBLIC         //
///////////////////////////

OAuthController.getOAuthProfile = getOAuthProfile;

///////////////////////////
//        HELPERS        //
///////////////////////////

function getOAuthProfile(options, req, res, next) {
  var accessToken = req.body.accessToken;
  var oAuthUserId = req.user;
  var profilePromise;

  req.log.info('Fetching OAuth profile');

  switch (req.body.oAuthProvider) {
    case 'google':
      profilePromise = getGoogleProfile(accessToken);
      break;
    case 'facebook':
      profilePromise = getFacebookProfile(options, accessToken, oAuthUserId);
      break;
  }

  profilePromise.then(function(profile) {
    sendResponse(options, req, res, profile);
  }).catch(next);
}

function getGoogleProfile(accessToken) {
  return jsonRequest({
    method: 'GET',
    uri: 'https://www.googleapis.com/userinfo/v2/me',
    headers: {
      Authorization: 'Bearer ' + accessToken
    }
  });
}

function getFacebookProfile(options, accessToken, oAuthUserId) {
  return jsonRequest(util.format(
    'https://graph.facebook.com/v2.4/%s?fields=%s&access_token=%s',
    oAuthUserId,
    options.facebookProfileFields,
    accessToken
  ));
}

function jsonRequest(reqData) {
  return rp(reqData).then(parseBody);
}

function parseBody(body) {
  try {
    return Promise.resolve(JSON.parse(body));
  } catch (e) {
    return Promise.reject(
      new Error(util.format('Parsing error: %s, body= \n %s', e.message, body))
    );
  }
}