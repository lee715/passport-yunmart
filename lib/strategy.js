// Load modules.
var OAuth2Strategy = require('passport-oauth2')
var querystring = require('querystring')
var util = require('util')

function Strategy (options, verify) {
  options = options || {}
  options.authorizationURL = options.authorizationURL || 'https://secure.yunmart.com/cas/oauth2.0/authorize'
  options.tokenURL = options.tokenURL || 'https://secure.yunmart.com/cas/oauth2.0/accessToken'
  options.customHeaders = options.customHeaders || {}

  if (!options.customHeaders['User-Agent']) {
    options.customHeaders['User-Agent'] = options.userAgent || 'passport-yunmart'
  }

  OAuth2Strategy.call(this, options, verify)
  this.name = 'yunmart'
  this._userProfileURL = options.userProfileURL || 'https://secure.yunmart.com/cas/oauth2.0/profile'

  this._oauth2.getAuthorizeUrl = function (params) {
    params = params || {}
    params['client_id'] = this._clientId
    return this._baseSite + this._authorizeUrl + '?' + querystring.stringify(params)
  }
  this._oauth2.getOAuthAccessToken = function (code, params, callback) {
    params = params || {}
    params['client_id'] = this._clientId
    params['client_secret'] = this._clientSecret
    params['code'] = code

    var post_data = querystring.stringify(params)

    this._request('GET', this._getAccessTokenUrl() + '?' + post_data, null, null, null, function (error, data, response) {
      if (error) {
        callback(error)
      } else {
        var results = querystring.parse(data)
        var access_token = results['access_token']
        var refresh_token = results['refresh_token']
        delete results['refresh_token']
        callback(null, access_token, refresh_token, results) // callback results =-=
      }
    })
  }
}

// Inherit from `OAuth2Strategy`.
util.inherits(Strategy, OAuth2Strategy)

Strategy.prototype.userProfile = function (accessToken, done) {
  this._oauth2._request('GET', this._userProfileURL + '?access_token=' + accessToken, null, null, null, function (err, body, res) {
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
