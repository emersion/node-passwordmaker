var crypto = require('crypto');
var l33t = require('./lib/l33t');
var hashutils = require('./lib/hashutils');

function generate(opts) {
	// For non-hmac algorithms, the key is master password and data concatenated
	var usingHMAC = opts.hashAlgorithm.indexOf('hmac') >= 0;
	if (!usingHMAC) {
		opts.key += opts.data;
	}

	// Apply l33t before the algorithm?
	if (opts.whereToUseL33t == 'both' || opts.whereToUseL33t == 'before-hashing') {
		opts.key = l33t.convert(opts.l33tLevel, opts.key);
		if (usingHMAC) {
			opts.data = l33t.convert(opts.l33tLevel, opts.data); // new for 0.3; 0.2 didn't apply l33t to _data_ for HMAC algorithms
		}
	}

	// Apply the algorithm
	var hash;
	if (usingHMAC) {
		hash = crypto.createHmac(opts.hashAlgorithm.replace('hmac-', ''), opts.key);
		hash.update(opts.data, 'utf8');
	} else {
		hash = crypto.createHash(opts.hashAlgorithm);
		hash.update(opts.key, 'utf8');
	}
	var password = hashutils.rstr2any(hash.digest('binary'), opts.charset);

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
