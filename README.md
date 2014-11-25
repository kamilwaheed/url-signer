# url-signer #

Tiny library for signing and validating URLs. Also exposes an Express middleware which is optional to use.

Originally developed for [Quixel](http://quixel.se).

Inspired from [sign-url](https://www.npmjs.org/package/sign-url) and [signed](https://www.npmjs.org/package/signed) both of which didn't really float the boat.

## Usage ##

### Initializing the singleton ###

```javascript
var signer = require('url-signer');

signer.init({
  privateKey: "mySuperSecurePrivateKey", // required
  algorithm: "sha256", // optional
  digest: "base64", // optional
  ttl: 3600 // optional
});
```

### Signing a URL ###

```javascript
var signedUrl = signer.getSignedUrl("http://site.com?id=50&accessToken=ae75ofjb7402");
```

### Verifying a URL ###

```javascript
var valid = signer.verifySignedUrl(signedUrl);
if (valid === true) {
  // all good; serve the secure payload
} else if (valid === 'expired') {
  // the signed url was valid but has been expired
} else{
  // the signed url is invalid  
}
```

### Using the Express middleware ###

```javascript
// Using the default behavior of `signer.verifier()`
// Sends 403 if invalid
// Sends 410 if expired
app.get("/endpoint", signer.verifier(), function(req,res) {
  // all good!
  // res.sendStatus(200);
});

// Using the custom callbacks with `signer.verifier()`
app.get("/endpoint", signer.verifier({
  invalid: function(req, res) {
    // req.sendStatus(403);
  },
  expired: function(req, res) {
    // req.sendStatus(410);
  }  
}), function(req,res) {
  // all good!
  // res.sendStatus(200);
});

```


## History ##

### v0.1.3 ###
Type cast options.ttl to Number

### v0.1.2 ###
Cleaned up JSDoc comments

### v0.1.1 ###
Added some notes in README.md

### v0.1.0 ###
Initial release


## License ##

The MIT License (MIT)

Copyright (c) 2014 Kamil Waheed

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.