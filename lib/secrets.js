(function() {

var forge, secrets;

if(typeof module !== 'undefined' && module.exports) {
  forge = require('node-forge');
  secrets = require('secrets.js');
} else {
  forge = window.forge;
  secrets = window.secrets;
}

var Secrets = function(options) {
  options = options || {};
  this.passwordEncrypterKeySize = options.keySize || 256;
  this.forge = forge;
  this.sss = secrets;
}

Secrets.prototype.encryptWithPassword = function(message, password, cb) {
  try {

    var input = message;

    // 3DES key and IV sizes
    var keySize = 24;
    var ivSize = 8;

    // get derived bytes
    // Notes:
    // 1. If using an alternative hash (eg: "-md sha1") pass
    //   "forge.md.sha1.create()" as the final parameter.
    // 2. If using "-nosalt", set salt to null.
    var salt = this.forge.random.getBytesSync(8);
    // var md = forge.md.sha1.create(); // "-md sha1"
    var derivedBytes = this.forge.pbe.opensslDeriveBytes(
      password, salt, keySize + ivSize/*, md*/);
    var buffer = this.forge.util.createBuffer(derivedBytes);
    var key = buffer.getBytes(keySize);
    var iv = buffer.getBytes(ivSize);

    var cipher = this.forge.cipher.createCipher('3DES-CBC', key);
    cipher.start({iv: iv});
    cipher.update(this.forge.util.createBuffer(input, 'binary'));
    var result = cipher.finish();

    if (result === false) {
      throw new Error('Could not encrypt');
    }

    var output = this.forge.util.createBuffer();

    // if using a salt, prepend this to the output:
    if(salt !== null) {
      output.putBytes('Salted__'); // (add to match openssl tool output)
      output.putBytes(salt);
    }
    output.putBuffer(cipher.output);

    var base64 = this.forge.util.encode64(output.data);

    cb(null, base64);
  } catch(e) {
    cb(e);
  }
};

Secrets.prototype.decryptWithPassword = function(message, password, cb) {
  try {

    var input = this.forge.util.decode64(message);

    // parse salt from input
    input = this.forge.util.createBuffer(input, 'binary');
    // skip "Salted__" (if known to be present)
    input.getBytes('Salted__'.length);
    // read 8-byte salt
    var salt = input.getBytes(8);

    // Note: if using "-nosalt", skip above parsing and use
    // var salt = null;

    // 3DES key and IV sizes
    var keySize = 24;
    var ivSize = 8;

    var derivedBytes = this.forge.pbe.opensslDeriveBytes(
      password, salt, keySize + ivSize);
    var buffer = this.forge.util.createBuffer(derivedBytes);
    var key = buffer.getBytes(keySize);
    var iv = buffer.getBytes(ivSize);

    var decipher = this.forge.cipher.createDecipher('3DES-CBC', key);
    decipher.start({iv: iv});
    decipher.update(input);
    var result = decipher.finish(); // check 'result' for true/false

    if (result === false) {
      throw new Error('Could not decrypt');
    }

    cb(null, decipher.output);
  } catch(e) {
    cb(e);
  }  
};

Secrets.prototype.encryptWithPublicKey = function(message, publicKey, cb) {
  try {
    // 1. generate IV and 32 bytes symmetric key for AES-256
    var key = this.forge.random.getBytesSync(32);
    var iv = this.forge.random.getBytesSync(16);

    // 2. encrypt data using the key generated above and AES-256
    var cipher = this.forge.cipher.createCipher('AES-CBC', key);
    cipher.start({iv: iv});
    cipher.update(this.forge.util.createBuffer(message, 'raw'));
    cipher.finish();

    // 3. encrypt data with the public key using RSAES-OAEP/SHA-256
    var pk = this.forge.pki.publicKeyFromPem(publicKey);
    var encryptedKey = pk.encrypt(key, 'RSA-OAEP', {
      md: forge.md.sha256.create(),
    });

    // 4. bundle data as an object and encrypt with base64.
    var data = {
      iv: forge.util.encode64(iv),
      k: forge.util.encode64(encryptedKey),
      d: forge.util.encode64(cipher.output.data),
    };

    var encryptedMessage = this.forge.util.encode64(JSON.stringify(data));

    cb(null, encryptedMessage);
  } catch(e) {
    cb(e);
  }
};

Secrets.prototype.decryptWithPrivateKey = 
  function(encryptedMessage, privateKey, cb) {

  try {
    // 1. deserialize data
    var data = JSON.parse(this.forge.util.decode64(encryptedMessage));

    // 2. decrypt AES key
    var pk = this.forge.pki.privateKeyFromPem(privateKey);
    var encryptedKey = this.forge.util.decode64(data.k);
    var decryptedKey = pk.decrypt(encryptedKey, 'RSA-OAEP', {
      md: forge.md.sha256.create()
    });

    // 3. decode data using the key we just decrypted
    var decipher = this.forge.cipher.createDecipher('AES-CBC', decryptedKey);
    decipher.start({iv: forge.util.decode64(data.iv)});
    decipher.update(this.forge.util.createBuffer(
                    this.forge.util.decode64(data.d), 'raw'));
    decipher.finish();

    var decryptedMessage = decipher.output.data;

    cb(null, decryptedMessage);
  } catch(e) {
    cb(e);
  }
  
};

Secrets.prototype.split = function(message, numberOfShares, threshold, cb) {
  try {
    var hexMessage = this.sss.str2hex(message);
    var shares = this.sss.share(hexMessage, numberOfShares, threshold);
    cb(null, shares);
  } catch(e) {
    cb(e);
  }
};

Secrets.prototype.combine = function(shares, cb) {
  try {
    var hexMessage = this.sss.combine(shares);
    var message = this.sss.hex2str(hexMessage);
    cb(null, message);    
  } catch(e) {
    cb(e);
  }
};

if(typeof module !== 'undefined' && module.exports) {
  module.exports = Secrets;
} else if (typeof window !== 'undefined') {
  if (window.sshare === undefined) {
    window.sshare = {};
  }
  if (window.sshare.Secrets === undefined) {
    window.sshare.Secrets = Secrets;
  }
}

})();
