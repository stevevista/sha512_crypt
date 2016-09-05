"use strict";

function crypt(key, salt, rounds) {
	require('crypto') // use openssl

	salt = salt || '';
	if (rounds === undefined && typeof salt === 'number') {
		rounds = salt
		salt = ''
	}

	rounds = rounds || 1000;
	return require('./build/Release/sha512_crypt').crypt(key, salt, rounds);
}

function verify(pwd, hashed) {
	let p = hashed.split('$')
	if (p.length !== 5 || p[1] !== '6') {
		// only sha512 support
		return false
	}
	
	let rounds = parseInt(p[2].split('=')[1])
	let salt= p[3], hash = p[4]
	
	if (isNaN(rounds) || rounds > 1000000) {
		return false
	}
	
	let checksum = crypt(pwd, salt, rounds)
	return checksum === hashed
} 

exports.crypt = crypt;
exports.verify = verify;
