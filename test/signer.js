var should = require('should')
  , signer = require('../lib/signer')
  , faker = require('faker')
  , express = require('express')
  , request = require('supertest');

describe("signer", function() {
  var urlToSign = faker.internet.domainName()
    , privateKey = faker.internet.password();

  describe("Before calling init() with a privateKey", function() {
    it("#getUrlSignature() should throw", function() {
      signer.getUrlSignature.bind(signer, urlToSign).should.throw();
    });

    it("#getSignedUrl() should throw", function() {
      signer.getSignedUrl.bind(signer, urlToSign).should.throw();
    });

    it("#verifyUrlSignature() should throw", function() {
      signer.verifyUrlSignature.bind(signer, urlToSign).should.throw();
    });

    it("#verifySignedUrl() should throw", function() {
      signer.verifySignedUrl.bind(signer, urlToSign).should.throw();
    });
  });

  describe("After calling init() with a privateKey", function() {
    before(function() {
      signer.init({
        privateKey: privateKey
      });
    });

    it("#getUrlSignature() shouldn't throw", function() {
      signer.getUrlSignature.bind(signer, urlToSign).should.not.throw();
    });

    it("#getSignedUrl() shouldn't throw", function() {
      signer.getSignedUrl.bind(signer, urlToSign).should.not.throw();
    });

    it("#verifyUrlSignature() shouldn't throw", function() {
      signer.verifyUrlSignature.bind(signer, "", urlToSign).should.not.throw();
    });

    it("#verifySignedUrl() shouldn't throw", function() {
      signer.verifySignedUrl.bind(signer, urlToSign).should.not.throw();
    });
  });

  describe("Verifying signed url and signature after signing", function() {
    it("#verifyUrlSignature() should return true", function() {
      var signature = signer.getUrlSignature(urlToSign);
      signer.verifyUrlSignature(signature, urlToSign).should.be.true;
    });

    it("#verifySignedUrl() should return true", function() {
      var signedUrl = signer.getSignedUrl(urlToSign);
      signer.verifySignedUrl(signedUrl).should.be.true;
    });
  });

  describe("Already existing `expires` and `signature` query params on a URL are overridden", function() {
    var urlToSignWithExpiresAndSignature = urlToSign + "?expires=10&signature=abc";

    it("#verifySignedUrl() should return true", function() {
      var signedUrl = signer.getSignedUrl(urlToSignWithExpiresAndSignature);
      signer.verifySignedUrl(signedUrl).should.be.true;
    });
  });

  describe("Query params on a URL are cool", function() {
    var urlToSignWithSomeQueryParams = urlToSign + "?user=10&userAccessToken=someSuperSecretAccessToken";

    it("#verifySignedUrl() should return true", function() {
      var signedUrl = signer.getSignedUrl(urlToSignWithSomeQueryParams);
      signer.verifySignedUrl(signedUrl).should.be.true;
    });
  });

  describe("Verifying signed url and signature after signing with custom algorithm and digest", function() {
    before(function() {
      signer.init({
        privateKey: privateKey,
        algorithm: "sha1",
        digest: "hex"
      })
    });

    it("#verifyUrlSignature() should return true", function() {
      var signature = signer.getUrlSignature(urlToSign);
      signer.verifyUrlSignature(signature, urlToSign).should.be.true;
    });

    it("#verifySignedUrl() should return true", function() {
      var signedUrl = signer.getSignedUrl(urlToSign);
      signer.verifySignedUrl(signedUrl).should.be.true;
    });
  });

  describe("Tampering the signature and signed url", function() {
    it("#verifySignedUrl() should return false", function() {
      var signature = signer.getUrlSignature(urlToSign);
      signature += "t";
      signer.verifyUrlSignature(signature, urlToSign).should.be.false;
    });

    it("#verifySignedUrl() should return `invalid`", function() {
      var signedUrl = signer.getSignedUrl(urlToSign);
      signedUrl += "t";
      signer.verifySignedUrl(signedUrl).should.equal('invalid');
    });
  });

  describe("Setting a TTL of 1 second on signer and then waiting for 2 seconds", function() {
    before(function() {
      signer.init({
        privateKey: privateKey,
        ttl: 1
      });
    });

    it("#verifySignedUrl() should return `expired`", function(done) {
      this.timeout(2500);

      var signedUrl = signer.getSignedUrl(urlToSign);

      setTimeout(function() {
        signer.verifySignedUrl(signedUrl).should.equal("expired");
        done();
      }, 2000);
    });
  });

  describe("Setting a TTL of 0 seconds on signer (never expire) and then waiting for 2 seconds", function() {
    before(function() {
      signer.init({
        privateKey: privateKey,
        ttl: 0
      });
    });

    it("#verifySignedUrl() should return true", function(done) {
      this.timeout(2500);

      var signedUrl = signer.getSignedUrl(urlToSign);

      setTimeout(function() {
        signer.verifySignedUrl(signedUrl).should.be.true;
        done();
      }, 2000);
    });
  });

  describe("Express middleware", function() {
    var app
      , search
      , endpoint = "/endpoint"
      , endpointsearch = "?user=5&someOtherVar=value"
      , signerUrl = "";

    before(function() {
      signer.init({
        privateKey: privateKey,
        ttl: 3600
      });

      app = express();
      app.get(endpoint, signer.verifier(), function(req, res) {
        res.sendStatus(200);
      });
    });

    describe("GET signedUrl for a valid URL", function() {
      before(function() {
        signedUrl = signer.getSignedUrl(endpoint + endpointsearch);
      });

      it("respond with 200", function(done) {
        request(app)
          .get(signedUrl)
          .expect(200, done);
      });
    });

    describe("GET signedUrl for a tampered URL", function() {
      before(function() {
        signedUrl += "t";
      });

      it("respond with 403", function(done) {
        request(app)
          .get(signedUrl)
          .expect(403, done);
      });
    });

    describe("GET signedUrl for an expired URL", function() {
      before(function() {
        signer.init({
          privateKey: privateKey,
          ttl: 1
        });

        signedUrl = signer.getSignedUrl(endpoint + endpointsearch);
      });

      it("respond with 410", function(done) {
        this.timeout(2500);

        setTimeout(function() {
          request(app)
            .get(signedUrl)
            .expect(410, done);
        }, 2000);
      });
    });
  });
});