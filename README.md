# sha512_crypt

```js
var crypt=require('sha512_crypt')
var hash = crypt.crypt('abcd.1234', 500000)
var hash2 = crypt.crypt('abcd.1234', 'X/DkLMfo6R4fMtw6', 535000)
crypt.verify('abcd.1234', hash) === true
crypt.verify('abcd.1234', hash2) === true
```

## Features
* 10 times faster then use built-in crypto
* now only support sha512 with ronuds limits to (1000, 1000000)
