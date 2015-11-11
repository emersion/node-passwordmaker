# node-passwordmaker

A Node.js library for [Password Maker](http://passwordmaker.org/).

## Usage

```js
var makepwd = require('passwordmaker');

console.log(makepwd({
	hashAlgorithm: 'sha256',
	masterPassword: 'test',
	data: 'example.org',
	length: 8,
	charset: ''
}));
```
