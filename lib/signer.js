/**
 * Returns a singleton
 *
 * @module signer
 */

var url         = require('url')
  , crypto      = require('crypto')
  , querystring = require('querystring');

module.exports = exports = {
  _algorithm: "sha256",
  _digest: "base64",

  _ttl: 3600, // seconds

  _privateKey: "",

  /**
   * Initialize the signer singleton with a privateKey and other options
   *
   * Must be called first with the privateKey before calling any other functions
   * 
   * @param {Object} options            The options object
   * @param {String} options.privateKey The private key to hash the URLs with
   * @param {String} [options.algorithm="sha256"]  The algorithm to pass to [crypto.createHash(algorithm)]{@link http://nodejs.org/api/crypto.html#crypto_crypto_createhash_algorithm}
   * @param {String} [options.digest="base64"]     The digest to pass to [crypto.digest(encoding)]{@link http://nodejs.org/api/crypto.html#crypto_hash_digest_encoding}
   * @param {Number} [options.ttl=3600]        Time to live in seconds for the URL after which it should expire; 0 for never
   */
  init: function(options) {
    this._algorithm = options.algorithm || this._algorithm;
    this._digest = options.digest || this._digest;

    this._ttl = Number(options.ttl) >= 0 ? Number(options.ttl) : this._ttl;
    this._privateKey = options.privateKey;
  },

  /**
   * Sign a given URL and return the signature
   * 
   * @param  {String} urlToSign URL to sign
   * @throws {Error}            If init() is not called first with a privateKey
   * @return {String}           URL signature
   */
  getUrlSignature: function(urlToSign) {
    if (!this._privateKey.length) {
      throw new Error("Call init() with privateKey first");
    }

    return crypto
        .createHmac(this._algorithm, this._privateKey)
        .update(urlToSign, 'utf-8')
        .digest(this._digest);
  },

  /**
   * Sign a given URL and return a new URL having two additional query params: `expires`, `signature`
   *
   * `expires` is TTL seconds ahead of the time at whoch the URL was signed
   *
   * If the given URL already has `expires` or `signature` set as query params, they will be
   * overridden.
   * 
   * @param  {String} urlToSign The URL to sign
   * @throws {Error}            If init() is not called first with a privateKey
   * @return {String}           The new URL with `expires` and `signature` set as query params
   */
  getSignedUrl: function(urlToSign) {
    if (!this._privateKey.length) {
      throw new Error("Call init() with privateKey first");
    }

    var parsedUrl = url.parse(urlToSign, true)
      , urlQuery  = parsedUrl.query;

    delete(urlQuery.expires);
    delete(urlQuery.signature);

    if (this._ttl) {
      urlQuery.expires = Math.floor(new Date()/1000) + this._ttl;
      parsedUrl.search = querystring.stringify(urlQuery);
    }

    urlQuery.signature = this.getUrlSignature(parsedUrl.format());
    parsedUrl.search = querystring.stringify(urlQuery);

    return parsedUrl.format();
  },

  /**
   * Checks if the signature of a given URL matches the expected signature
   * 
   * @param  {String}  signature   The expected signature
   * @param  {Strign}  urlToVerify The URL to check
   * @throws {Error}            If init() is not called first with a privateKey
   * @return {Boolean}             Whether or not the signature is valid
   */
  verifyUrlSignature: function(signature, urlToVerify) {
    return signature === this.getUrlSignature(urlToVerify);
  },

  /**
   * Verifies a given URL by checking first if the signature is valid and then checking it has
   * not expired
   * 
   * @param  {String}         urlToVerify The URL to verify
   * @throws {Error}            If init() is not called first with a privateKey
   * @return {Boolean|String}             true, `expired`, or `invalid`
   */
  verifySignedUrl: function(urlToVerify) {
    var parsedUrl = url.parse(urlToVerify, true)
      , urlQuery = parsedUrl.query
      , signature = urlQuery.signature
      , expires = urlQuery.expires;

      delete(urlQuery.signature);

      parsedUrl.search = querystring.stringify(urlQuery);
      
      if (!this.verifyUrlSignature(signature, parsedUrl.format())) {
        return 'invalid';
      }
      
      if (expires && Math.floor(new Date()/1000) > expires) {
        return 'expired';
      }

      return true;
  },

  /**
   * Return the Express middleware
   *
   * @param  {Object}   options
   * @param  {Function} [options.invalid=sends 403] The callback with signature fn(req, res) to
   *                                                call when the request URL is invalid
   * @param  {Function} [options.expired=sends 410] The callback with signature fn(req, res) to
   *                                                call when the request URL is expired
   * @return {Function} Express middleware function
   */
  verifier: function(options) {
    var self = this;
    options = options || {};

    var callbacks = {
      invalid: options.invalid || function(req, res) {
        res.sendStatus(403); // Forbidden
      },
      expired: options.expired || function(req, res) {
        res.sendStatus(410); // Gone
      }
    };

    return function(req, res, next) {
      var url = req.originalUrl;

      var valid = self.verifySignedUrl(url);

      if (valid !== true && callbacks[valid]) {
        callbacks[valid](req, res);
      } else {
        next();
      }
    };
  }
};