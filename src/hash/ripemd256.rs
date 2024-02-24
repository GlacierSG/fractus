#[derive(Clone)]
pub struct Ripemd256 {
    state: [u32; 8],
    block: [u32; 16],
    size: usize,
}

impl Ripemd256 {
    pub const IV: [u32; 8] = [
        0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0x76543210, 0xfedcba98, 0x89abcdef,
        0x01234567,
    ];

    pub fn new() -> Self {
        Self {
            state: Self::IV,
            block: [0; 16],
            size: 0,
        }
    }

    pub fn from(hash: &[u8; 32]) -> Self {
        Self {
            state: [0, 4, 8, 12, 16, 20, 24, 28]
                .map(|i| u32::from_le_bytes([hash[i], hash[i + 1], hash[i + 2], hash[i + 3]])),
            block: [0; 16],
            size: 0,
        }
    }

    pub fn update(&mut self, input_buf: impl AsRef<[u8]>) -> () {
        let mut offset: usize = self.size % 64;
        self.size += input_buf.as_ref().len();

        for &v in input_buf.as_ref() {
            if offset % 4 == 0 {
                self.block[offset >> 2] = v as u32;
            } else {
                self.block[offset >> 2] |= (v as u32) << ((offset & 3) << 3);
            }
            offset += 1;

            if offset % 64 == 0 {
                self.transform();
                offset = 0;
            }
        }
    }

    fn transform(&mut self) {
        let func = [
            |b: u32, c: u32, d: u32| b ^ c ^ d,
            |b: u32, c: u32, d: u32| (b & c) | (!b & d),
            |b: u32, c: u32, d: u32| (b | !c) ^ d,
            |b: u32, c: u32, d: u32| (b & d) | (c & !d),
            |b: u32, c: u32, d: u32| (b & d) | (c & !d),
            |b: u32, c: u32, d: u32| (b | !c) ^ d,
            |b: u32, c: u32, d: u32| (b & c) | (!b & d),
            |b: u32, c: u32, d: u32| b ^ c ^ d,
        ];
        let shifts = [
            [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8],
            [7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12],
            [11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5],
            [11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12],
            [8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6],
            [9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11],
            [9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5],
            [15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8],
        ];
        let idx = [
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
            [7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8],
            [3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12],
            [1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2],
            [5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12],
            [6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2],
            [15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13],
            [8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14],
        ];
        let adds = [
            0, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0,
        ];

        let mut h = [0; 4];
        h.copy_from_slice(&self.state[..4]);

        let mut k = [0; 4];
        k.copy_from_slice(&self.state[4..]);
        for i in 0..4 {
            for j in 0..16 {
                let t = (16 - j as i32) as usize;
                let [i0, i1, i2, i3] = [t % 4, (t + 1) % 4, (t + 2) % 4, (t + 3) % 4];
                h[i0] = h[i0]
                    .wrapping_add(func[i](h[i1], h[i2], h[i3]))
                    .wrapping_add(self.block[idx[i][j]])
                    .wrapping_add(adds[i]);
                h[i0] = h[i0].rotate_left(shifts[i][j]);
            }
            for j in 0..16 {
                let t = (16 - j as i32) as usize;
                let [i0, i1, i2, i3] = [t % 4, (t + 1) % 4, (t + 2) % 4, (t + 3) % 4];
                k[i0] = k[i0]
                    .wrapping_add(func[i + 4](k[i1], k[i2], k[i3]))
                    .wrapping_add(self.block[idx[i + 4][j]])
                    .wrapping_add(adds[i + 4]);
                k[i0] = k[i0].rotate_left(shifts[i + 4][j]);
            }

            let a = h[i];
            h[i] = k[i];
            k[i] = a;
        }

        for i in 0..4 {
            self.state[i] = self.state[i].wrapping_add(h[i]);
            self.state[i + 4] = self.state[i + 4].wrapping_add(k[i]);
        }
    }

    pub fn finalize(&mut self) -> [u8; 32] {
        let pad = super::ripemd256::padding(self.size);
        self.update(&pad);

        let mut digest = [0u8; 32];
        let mut j = 0;
        for i in 0..8 {
            [digest[j], digest[j + 1], digest[j + 2], digest[j + 3]] = self.state[i].to_le_bytes();
            j += 4;
        }

        digest
    }
}

/// Compute ripemd256 hash
/// ```
/// use fractus::hash::ripemd256;
/// assert_eq!(&ripemd256::compute(b"abc"), b"\xaf\xbdn\"\x8b\x9d\x8c\xbb\xce\xf5\xca-\x03\xe6\xdb\xa1\n\xc0\xbc}\xcb\xe4h\x0e\x1eB\xd2\xe9uE\x9be");
/// ```
pub fn compute(data: impl AsRef<[u8]>) -> [u8; 32] {
    let mut m = Ripemd256::new();
    m.update(data.as_ref());
    m.finalize()
}

/// Compute ripemd256 length extension attack
/// ```
/// use fractus::hash::ripemd256;
/// let secret = b"abc";
/// let hash = ripemd256::compute(&secret);
/// let added_msg = b"cde";
/// let ext = ripemd256::extend(&hash, secret.len(), added_msg);
/// let pad = ripemd256::padding(secret.len());
/// let mut combined = secret.to_vec();
/// combined.extend(pad);
/// combined.extend(added_msg);
/// let combined_hash = ripemd256::compute(combined);
/// assert_eq!(combined_hash, ext);
/// ```
pub fn extend(
    original_hash: &[u8; 32],
    original_size: usize,
    extended_data: impl AsRef<[u8]>,
) -> [u8; 32] {
    let mut m = Ripemd256::from(original_hash);

    let pad_length: usize = padding_len(original_size);
    m.size = original_size + pad_length;

    m.update(extended_data);
    m.finalize()
}

/// Compute ripemd256 padding length for the hashed data length
pub fn padding_len(data_len: usize) -> usize {
    let offset = (data_len % 64) as usize;
    if offset < 56 {
        64 - offset
    } else {
        128 - offset
    }
}

/// Compute ripemd256 padding for the given length
pub fn padding(data_len: usize) -> Vec<u8> {
    let bit_len = data_len.wrapping_mul(8);
    let pad_length: usize = padding_len(data_len);

    let mut pad = vec![0; pad_length];
    pad[0] = 0x80;
    let p: [u8; 8] = (bit_len as u64).to_be_bytes();
    for i in 0..8 {
        pad[pad_length - i - 1] = p[i];
    }
    pad
}

#[cfg(test)]
mod test {
    use crate::hash::ripemd256;

    fn from_hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect::<Vec<u8>>()
    }

    #[test]
    fn hash() {
        let expected = [
            (
                0,
                "02ba4c4e5f8ecd1877fc52d64d30e37a2d9774fb1e5d026380ae0168e3c5522d",
            ),
            (
                1,
                "f9333e45d857f5d90a91bab70a1eba0cfb1be4b0783c9acfcd883a9134692925",
            ),
            (
                2,
                "d58b37584c74dffcf7f903bd378611a68971ad176ce620873be6048d8917df7e",
            ),
            (
                127,
                "f743468ffaf711729ed8a37bd700e23747ed6345c21deec78c5d623f67212849",
            ),
            (
                128,
                "33b9c6f5f888e077f81067c9c082bf0da7ef9738e20d69b0864418ce568cd32c",
            ),
            (
                129,
                "cb3b0732168add75f05b402303768259103294ff8e998f615bc96af9e8a3af05",
            ),
            (
                10000,
                "7208062d43f858203f060ae0596b118db46277d33f1961baba95d8b1e56881f7",
            ),
        ]
        .map(|x| (x.0, from_hex(x.1)));
        for (i, hash) in expected {
            assert_eq!(&hash, &ripemd256::compute(b"a".repeat(i)));
        }
    }

    #[test]
    fn extend() {
        for i in 0..100 {
            for j in 0..100 {
                let secret = b"b".repeat(i);
                let hash = ripemd256::compute(&secret);
                let added_msg = b"c".repeat(j);
                let ext = ripemd256::extend(&hash, secret.len(), &added_msg);
                let pad = ripemd256::padding(secret.len());
                let mut combined = secret.clone();
                combined.extend(pad);
                combined.extend(&added_msg);
                let combined_hash = ripemd256::compute(combined);
                assert_eq!(combined_hash, ext);
            }
        }
    }
}
