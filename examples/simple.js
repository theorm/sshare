var workflow, secrets, sshare;

if(typeof module !== 'undefined' && module.exports) {
  sshare = require('../index');
}

workflow = new sshare.Workflow(),
secrets = new sshare.Secrets();


var password = 'cool bananas';
var originalMessage = 'Exercitation est aute eiusmod ex laborum sint pariatur.' 
  +' Culpa ut minim consequat do laboris elit occaecat id.';

var privateKey = 
'-----BEGIN RSA PRIVATE KEY-----' +
'MIICXQIBAAKBgQDlOJu6TyygqxfWT7eLtGDwajtNFOb9I5XRb6khyfD1Yt3YiCgQ' +
'WMNW649887VGJiGr/L5i2osbl8C9+WJTeucF+S76xFxdU6jE0NQ+Z+zEdhUTooNR' +
'aY5nZiu5PgDB0ED/ZKBUSLKL7eibMxZtMlUDHjm4gwQco1KRMDSmXSMkDwIDAQAB' +
'AoGAfY9LpnuWK5Bs50UVep5c93SJdUi82u7yMx4iHFMc/Z2hfenfYEzu+57fI4fv' +
'xTQ//5DbzRR/XKb8ulNv6+CHyPF31xk7YOBfkGI8qjLoq06V+FyBfDSwL8KbLyeH' +
'm7KUZnLNQbk8yGLzB3iYKkRHlmUanQGaNMIJziWOkN+N9dECQQD0ONYRNZeuM8zd' +
'8XJTSdcIX4a3gy3GGCJxOzv16XHxD03GW6UNLmfPwenKu+cdrQeaqEixrCejXdAF' +
'z/7+BSMpAkEA8EaSOeP5Xr3ZrbiKzi6TGMwHMvC7HdJxaBJbVRfApFrE0/mPwmP5' +
'rN7QwjrMY+0+AbXcm8mRQyQ1+IGEembsdwJBAN6az8Rv7QnD/YBvi52POIlRSSIM' +
'V7SwWvSK4WSMnGb1ZBbhgdg57DXaspcwHsFV7hByQ5BvMtIduHcT14ECfcECQATe' +
'aTgjFnqE/lQ22Rk0eGaYO80cc643BXVGafNfd9fcvwBMnk0iGX0XRsOozVt5Azil' +
'psLBYuApa66NcVHJpCECQQDTjI2AQhFc1yRnCU/YgDnSpJVm1nASoRUnU8Jfm3Oz' +
'uku7JUXcVpt08DFSceCEX9unCuMcT72rAQlLpdZir876' +
'-----END RSA PRIVATE KEY-----';

var publicKey = 
'-----BEGIN PUBLIC KEY-----' +
'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDlOJu6TyygqxfWT7eLtGDwajtN' +
'FOb9I5XRb6khyfD1Yt3YiCgQWMNW649887VGJiGr/L5i2osbl8C9+WJTeucF+S76' +
'xFxdU6jE0NQ+Z+zEdhUTooNRaY5nZiu5PgDB0ED/ZKBUSLKL7eibMxZtMlUDHjm4' +
'gwQco1KRMDSmXSMkDwIDAQAB' +
'-----END PUBLIC KEY-----';

if(typeof module !== 'undefined' && module.exports) {
  function notify(orig, result, statuses) {
    console.log('Original message: ', orig);
    console.log('Reuslting message: ', result);

    Object.keys(statuses).forEach(function(k) {
      console.log(k + ': ', statuses[k]);
    });
  }
} else {
  function notify(orig, result, statuses) {
    document.addEventListener("DOMContentLoaded", function(event) {
      var el = document.createElement('div');
      el.innerHTML = 'Original message: ' + orig;
      document.body.appendChild(el);

      el = document.createElement('div');
      el.innerHTML = 'Result message: ' + result;
      document.body.appendChild(el);

      Object.keys(statuses).forEach(function(k) {
        el = document.createElement('div');
        el.innerHTML = k + ': ' + statuses[k] + ' ms.';
        document.body.appendChild(el);
      });
    });

  }  
}


var statuses = {}, s, e;

s = new Date();

secrets.encryptWithPassword(privateKey, password, 
  function(err, encryptedPrivateKey) {

  e = new Date();
  statuses['private_key_encrypted'] = e - s;

  s = new Date();

  var encryptedShares = [];
  workflow.splitAndEncrypt(originalMessage, [publicKey, publicKey, publicKey], 
                           3, function(err, chunks) {
    
    e = new Date();
    statuses['split_and_enrypted'] = e - s;

    s = new Date();

    if (err) {
      console.log(err.stack);
      console.error(err);
    } else {
      console.log(chunks);

      s = new Date();

      workflow.combineEncryptedShares(chunks, encryptedPrivateKey, password, function(err, message) {
        
        e = new Date();
        statuses['decrypt_and_combine'] = e - s;

        if (err) {
          console.log(err.stack);
          console.error(err);
        }
        notify(originalMessage, message, statuses);
      });
    }
  });
});
