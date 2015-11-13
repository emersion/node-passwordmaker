var assert = require('assert');
var makePassword = require('..');
var extend = require('extend');

describe('passwordmaker', function () {
	var baseOpts = {
		masterPassword: 'test',
		length: 8,
		charset: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789`~!@#$%^&*()_-+={}|[]\\:";\'<>?,./',
		data: 'example.org'
	};

	it('should return the correct password for hash md4', function () {
		var opts = extend({}, baseOpts, {
			hashAlgorithm: 'md4'
		});
		assert.equal(makePassword(opts), 'E#7.=d#Z');
	});

	it('should return the correct password for hash hmac-md4', function () {
		var opts = extend({}, baseOpts, {
			hashAlgorithm: 'hmac-md4'
		});
		assert.equal(makePassword(opts), 'IKi8;2JX');
	});

	it('should return the correct password for hash md5', function () {
		var opts = extend({}, baseOpts, {
			hashAlgorithm: 'md5'
		});
		assert.equal(makePassword(opts), 'E5(zr"/q');
	});

	it('should return the correct password for hash hmac-md5', function () {
		var opts = extend({}, baseOpts, {
			hashAlgorithm: 'hmac-md5'
		});
		assert.equal(makePassword(opts), 'J0Zg;w%Y');
	});

	it('should return the correct password for hash sha1', function () {
		var opts = extend({}, baseOpts, {
			hashAlgorithm: 'sha1'
		});
		assert.equal(makePassword(opts), '$7C]3`#b');
	});

	it('should return the correct password for hash hmac-sha1', function () {
		var opts = extend({}, baseOpts, {
			hashAlgorithm: 'hmac-sha1'
		});
		assert.equal(makePassword(opts), 'E2/.R}F<');
	});

	it('should return the correct password for hash sha256', function () {
		var opts = extend({}, baseOpts, {
			hashAlgorithm: 'sha256'
		});
		assert.equal(makePassword(opts), '\'j{}TUh;');
	});

	it('should return the correct password for hash hmac-sha256', function () {
		var opts = extend({}, baseOpts, {
			hashAlgorithm: 'hmac-sha256'
		});
		assert.equal(makePassword(opts), '>2qA1V-!');
	});

	it('should return the correct password for hash ripemd160', function () {
		var opts = extend({}, baseOpts, {
			hashAlgorithm: 'ripemd160'
		});
		assert.equal(makePassword(opts), 'EHB6EGPe');
	});

	it('should return the correct password for hash hmac-ripemd160', function () {
		var opts = extend({}, baseOpts, {
			hashAlgorithm: 'hmac-ripemd160'
		});
		assert.equal(makePassword(opts), '@N,.*<jy');
	});

	it('should return the correct password for hash sha256 and data with special chars', function () {
		var opts = extend({}, baseOpts, {
			hashAlgorithm: 'sha256',
			data: 'çà@-a.&"'
		});
		assert.equal(makePassword(opts), 'iZnG%aJ]');
	});

	it('should return the correct password for hash sha256 with modifier', function () {
		var opts = extend({}, baseOpts, {
			hashAlgorithm: 'sha256',
			modifier: 'modifier'
		});
		assert.equal(makePassword(opts), 'cRzG{Hio');
	});

	it('should return the correct password for hash sha256 with modifier with special chars', function () {
		var opts = extend({}, baseOpts, {
			hashAlgorithm: 'sha256',
			modifier: 'éàa@#°ç'
		});
		assert.equal(makePassword(opts), 'G1CN$Vt\\');
	});

	it('should return the correct password for hash sha256 with l33t', function () {
		var opts = extend({}, baseOpts, {
			hashAlgorithm: 'sha256',
			whereToUseL33t: 'before-hashing',
			l33tLevel: 1
		});
		assert.equal(makePassword(opts), '-(ke_Z~1');
	});
});
