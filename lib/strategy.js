// Load modules.
var OAuth2Strategy = require('passport-oauth2')
var querystring = require('querystring')
var util = require('util')

function Strategy (options, verify) {
  options = options || {}
  options.authorizationURL = options.authorizationURL || 'https://open.qiye.163.com/a/oauth2/authorize'
  options.tokenURL = options.tokenURL || 'https://open.qiye.163.com/a/oauth2/token'
  options.customHeaders = options.customHeaders || {}

  if (!options.customHeaders['User-Agent']) {
    options.customHeaders['User-Agent'] = options.userAgent || 'passport-qiye163'
  }

  OAuth2Strategy.call(this, options, verify)
  this.name = 'qiyi163'

  this._oauth2.getAuthorizeUrl = function (params) {
    params = params || {}
    params['client_id'] = this._clientId
    params['response_type'] = 'code'
    return this._baseSite + this._authorizeUrl + '?' + querystring.stringify(params)
  }
  this._oauth2.getOAuthAccessToken = function (code, params, callback) {
    params = params || {}
    params['client_id'] = this._clientId
    params['client_secret'] = this._clientSecret
    params['code'] = code
    params['grant_type'] = 'authorization_code'

    var post_data = querystring.stringify(params)
    var self = this
    this._request('GET', this._getAccessTokenUrl() + '?' + post_data, null, null, null, function (error, data, response) {
      if (error) {
        callback(error)
      } else {
        var results = querystring.parse(data)
        var access_token = results['access_token']
        var refresh_token = results['refresh_token']
        delete results['refresh_token']
        self._userProfileURL = results.resource_uri
        callback(null, access_token, refresh_token, results) // callback results =-=
      }
    })
  }
}

// Inherit from `OAuth2Strategy`.
util.inherits(Strategy, OAuth2Strategy)

Strategy.prototype.userProfile = function (accessToken, done) {
  var qstr = querystring.stringify({
    token: accessToken,
    client_id: this._clientId,
    op: 'getLoginAccount'
  })
  this._oauth2._request('GET', this._oauth2._userProfileURL + '?' + qstr, null, null, null, function (err, body, res) {
    var json

    if (err) {
      return done(new Error('Failed to fetch user profile'))
    }

    try {
      json = JSON.parse(body)
      json.attributes.forEach(function (obj) {
        Object.keys(obj).forEach(function (key) {
          json[key] = obj[key]
        })
      })
      return done(null, json)
    } catch (ex) {
      return done(new Error('Failed to parse user profile'))
    }
  })
}

// Expose constructor.
module.exports = Strategy
