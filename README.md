
# Fractus
Fractus is a cryptographic attack library written in rust. It is also available through python

## Run
### Rust
`cargo add fractus`
```rust
use fractus::sha2_256;

let m = b"abc";
let h = sha2_256::compute(&m);
let e = b"cde";
let mut c = m.to_vec();
c.extend(sha2_256::padding(m.len()));
c.extend(e);
let e = sha2_256::extend(&h, m.len(), e);
assert_eq!(e, sha2_256::compute(c));
```

### Python
```python
from fractus import sha2_256

m = b'secret'+b'abc'
h = sha2_256.compute(m)
e = b'test'
assert sha2_256.extend(h, len(m), e) == sha2_256.compute(m + sha2_256.padding(len(m)) + e)
```

## Develop
### Rust
`cargo test`
### Python
in a python virtual environment:

`maturin develop --features python`

## Features
### Length Extension Attack
- [x] MD4
- [x] MD5
- [x] SHA0
- [x] SHA1
- [x] SHA2_256
- [x] SHA2_512
- [x] Ripemd128
- [x] Ripemd160
- [x] Ripemd256
- [x] Ripemd320
- [x] Whirlpool