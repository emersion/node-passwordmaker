var l33t = require('./lib/l33t');
var sha256 = require('./lib/sha256');
var sha1 = require('./lib/sha1');
var md4 = require('./lib/md4');
var md5 = require('./lib/md5');
var md5_v6 = require('./lib/md5_v6');
var ripemd160 = require('./lib/ripemd160');

function generate(opts) {
	// For non-hmac algorithms, the key is master password and data concatenated
	var usingHMAC = opts.hashAlgorithm.indexOf('hmac') >= 0;
	if (!usingHMAC) {
		opts.key += opts.data;
	}

	// Apply l33t before the algorithm?
	if (opts.whereToUseL33t == 'both' || opts.whereToUseL33t == 'before-hashing') {
		key = l33t.convert(opts.l33tLevel, opts.key);
		if (usingHMAC) {
			opts.data = l33t.convert(opts.l33tLevel, opts.data); // new for 0.3; 0.2 didn't apply l33t to _data_ for HMAC algorithms
		}
	}

	// Apply the algorithm
	var password = '';
	switch(opts.hashAlgorithm) {
		case 'sha256':
		password = sha256.any_sha256(opts.key, opts.charset);
		break;
		case 'hmac-sha256':
		password = sha256.any_hmac_sha256(opts.key, opts.data, opts.charset, true);
		break;
		case 'hmac-sha256_fix':
		password = sha256.any_hmac_sha256(opts.key, opts.data, opts.charset, false);
		break;
		case 'sha1':
		password = sha1.any_sha1(opts.key, opts.charset);
		break;
		case 'hmac-sha1':
		password = sha1.any_hmac_sha1(opts.key, opts.data, opts.charset);
		break;
		case 'md4':
		password = md4.any_md4(opts.key, opts.charset);
		break;
		case 'hmac-md4':
		password = md4.any_hmac_md4(opts.key, opts.data, opts.charset);
		break;
		case 'md5':
		password = md5.any_md5(opts.key, opts.charset);
		break;
		case 'md5_v6':
		password = md5_v6.hex_md5(opts.key, opts.charset);
		break;
		case 'hmac-md5':
		password = md5.any_hmac_md5(opts.key, opts.data, opts.charset);
		break;
		case 'hmac-md5_v6':
		password = md5_v6.hex_hmac_md5(opts.key, opts.data, opts.charset);
		break;
		case 'rmd160':
		password = ripemd160.any_rmd160(opts.key, opts.charset);
		break;
		case 'hmac-rmd160':
		password = ripemd160.any_hmac_rmd160(opts.key, opts.data, opts.charset);
		break;
	}

	// Apply l33t after the algorithm?
	if (opts.whereToUseL33t == 'both' || opts.whereToUseL33t == 'after-hashing') {
		password = l33t.convert(opts.l33tLevel, password);
	}

	return password;
}

module.exports = function (opts) {
	if (!opts.hashAlgorithm) {
		throw new Error('No hash algorithm specified');
	}
	if (!opts.masterPassword) {
		throw new Error('No master password specified');
	}
	if (!opts.length) {
		throw new Error('No output length specified');
	}
	if (!opts.charset) {
		throw new Error('No charset specified');
	}
	if (opts.charset.length < 2) {
		// Never *ever, ever* allow the charset's length<2 else
		// the hash algorithms will run indefinitely
		throw new Error('Charset length must be greater than 2');
	}

	opts.data = opts.data || '';
	opts.username = opts.username || '';
	opts.modifier = opts.modifier || '';
	opts.whereToUseL33t = opts.whereToUseL33t || 'never';
	opts.l33tLevel = opts.l33tLevel || 0;
	opts.prefix = opts.prefix || '';
	opts.suffix = opts.suffix || '';

	// Calls generate() n times in order to support passwords
	// of arbitrary length regardless of character set length.
	var password = '';
	var count = 0;
	while (password.length < opts.length) {
		var generateOpts = {
			hashAlgorithm: opts.hashAlgorithm,
			key: opts.masterPassword,
			data: opts.data + opts.username + opts.modifier,
			whereToUseL33t: opts.whereToUseL33t,
			l33tLevel: opts.l33tLevel,
			length: opts.length,
			charset: opts.charset,
			prefix: opts.prefix,
			suffix: opts.suffix
		};

		// To maintain backwards compatibility with all previous versions of passwordmaker,
		// the first call to generate() must use the plain 'key'.
		// Subsequent calls add a number to the end of the key so each iteration
		// doesn't generate the same hash value.
		if (count > 0) {
			generateOpts.key += '\n' + count;
		}

		password += generate(generateOpts);

		count++;
	}

	password = opts.prefix + password;
	password = password.substring(0, opts.length - opts.suffix.length) + opts.suffix;

	return password.substring(0, opts.length);
};
