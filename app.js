var crypto = require('crypto');
var aesjs = require('aes-js');
var etext = 'tHL92o65fQlhcxBcRbAIEW2zAvRj0NzB1xuITZb/auBE8F19K1picaLjABeAEsqX';
var skey = 'a92463241A2C438f94G17bF91V668mC4';

function removeCipherNoise(data, key) {
	var keyHash = getSha1Hash(key);
	var keyLen = keyHash.length;
	var dataLen = data.length;
	var buffer = [];
	var dataBuffer = new Buffer(data);
	for (var i = 0, j = 0, len = dataLen; i < len; ++i, ++j) {
		if (j >= keyLen){j = 0;}
		var temp = dataBuffer[i] - keyHash[j];
		if (temp < 0) {
			temp = temp + 256;
		}
		buffer.push(temp);
	}
	return buffer;
}
function getSha1Hash(key) {
	return new Buffer(crypto.createHash('sha1').update(key).digest('hex'));
}
function getMD5Hash(key) {
	return new Buffer(crypto.createHash('md5').update(key).digest('hex'));
}

function decryptbyaesjs(ciphertext, key)
{
	var mdKey = new Buffer(getMD5Hash(skey)); // passed
	var dataBytes = removeCipherNoise(Buffer.from(etext, 'base64'), mdKey); // passed
	var iv = new Buffer(dataBytes.slice(0, 16)); // passed
	dataBytes = dataBytes.slice(16); // passed

	// The counter mode of operation maintains internal state, so to
	// decrypt a new instance must be instantiated.
	var aesCtr = new aesjs.ModeOfOperation.cbc(mdKey, iv);
	var decryptedBytes = aesCtr.decrypt(dataBytes);
	
	// Convert our bytes back into text
	return aesjs.utils.utf8.fromBytes(decryptedBytes);
}

function decryptbymcrypt(ciphertext, key)
{
	var mdKey = new Buffer(getMD5Hash(skey)); // passed
	var dataBytes = removeCipherNoise(Buffer.from(etext, 'base64'), mdKey); // passed
	var iv = new Buffer(dataBytes.slice(0, 16)); // passed
	dataBytes = dataBytes.slice(16); // passed

	var desEcb = new MCrypt('rijndael-128', 'cbc');

	desEcb.open(mdKey, iv); // we are set the key
	return desEcb.decrypt(new Buffer(dataBytes)).toString();
}
console.log(decryptbyaesjs(etext, skey));