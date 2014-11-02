(function() {

var Bluebird, Secrets;

if(typeof module !== 'undefined' && module.exports) {
  Bluebird = require('bluebird');
  Secrets = require('./secrets');
} else {
  Bluebird = window.P;
  Secrets = window.sshare.Secrets;
}

var Workflow = function() {
  this.promises = Bluebird;
  this.secrets = this.promises.promisifyAll(new Secrets());
}

Workflow.prototype.splitAndEncrypt = 
  function(message, publicKeys, threshold, cb) {

  // 1. split message.
  this.secrets.splitAsync(message, publicKeys.length, threshold)
    .bind(this)
    .then(function(shares) {

      // 2. encrypt each share with corresponding public key.
      var encrypters = [];
      shares.forEach(function(share, idx) {
        var pk = publicKeys[idx];
        var encrypter = this.secrets.encryptWithPublicKeyAsync(share, pk);
        encrypters.push(encrypter);
      }, this);

      return this.promises.all(encrypters);
    })
    .then(function(encryptedShares) {
      // 3. all good - return existing shares.
      cb(null, encryptedShares);
    })
    .then(null, cb);
};

Workflow.prototype.transferShare = 
  function(encryptedShare, encryptedPrivateKey, password, 
           receiverPublicKey, cb) {
  
  // 1. decrypt private key
  this.secrets.decryptWithPasswordAsync(encryptedPrivateKey, password)
    .bind(this)
    .then(function(privateKey) {
      // 2. decrypt share with this private key
      return this.secrets.decryptWithPrivateKeyAsync(encryptedShare, privateKey);
    })
    .then(function(share) {
      // 3. encrypt share with receiver's public key
      return this.secrets.encryptWithPublicKeyAsync(share, receiverPublicKey);
    })
    .then(function(recieverEncryptedShare) {
      // 4. all good - return share encrypted with receiver's key
      cb(null, recieverEncryptedShare);
    })
    .then(null, cb);
};

Workflow.prototype.combineEncryptedShares = 
  function(encryptedShares, encryptedPrivateKey, password, cb) {

  // 1. decrypt private key
  this.secrets.decryptWithPasswordAsync(encryptedPrivateKey, password)
    .bind(this)
    .then(function(privateKey) {
      // 2. decrypt each share
      var decryptedSharePromises = [];
      encryptedShares.forEach(function(s) {
        var p = this.secrets.decryptWithPrivateKeyAsync(s, privateKey);
        decryptedSharePromises.push(p);
      }, this);

      return this.promises.all(decryptedSharePromises);
    })
    .then(function(decryptedShares) {
      // 3. combine shares
      return this.secrets.combineAsync(decryptedShares);
    })
    .then(function(message) {
      cb(null, message);
    })
    .then(null, cb);
};

if(typeof module !== 'undefined' && module.exports) {
  module.exports = Workflow;
} else if (typeof window !== 'undefined') {
  if (window.sshare === undefined) {
    window.sshare = {};
  }
  if (window.sshare.Workflow === undefined) {
    window.sshare.Workflow = Workflow;
  }
}

})();
