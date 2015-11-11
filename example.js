var makepwd = require('./index');

console.log(makepwd({
	hashAlgorithm: 'sha256',
	masterPassword: 'test',
	data: 'example.org',
	length: 8,
	charset: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789`~!@#$%^&*()_-+={}|[]\\:";\'<>?,./'
}));
