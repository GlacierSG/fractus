#[derive(Clone)]
pub struct Ripemd160 {
    state: [u32; 5],
    block: [u32; 16],
    size: usize,
}

impl Ripemd160 {
    pub const IV: [u32; 5] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];

    pub fn new() -> Self {
        Self {
            state: Self::IV,
            block: [0; 16],
            size: 0,
        }
    }

    pub fn from(hash: &[u8; 20]) -> Self {
        Self {
            state: [0, 4, 8, 12, 16]
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
            |b: u32, c: u32, d: u32| b ^ (c | !d),
            |b: u32, c: u32, d: u32| b ^ (c | !d),
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
            [9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6],
            [8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6],
            [9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11],
            [9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5],
            [15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8],
            [8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11],
        ];
        let idx = [
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
            [7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8],
            [3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12],
            [1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2],
            [4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13],
            [5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12],
            [6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2],
            [15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13],
            [8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14],
            [12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11],
        ];
        let adds = [
            0, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e, 0x50a28be6, 0x5c4dd124, 0x6d703ef3,
            0x7a6d76e9, 0,
        ];

        let mut h = self.state;
        for i in 0..5 {
            for j in 0..16 {
                let t = (20 - (j as i32) + 5 - (i as i32)) as usize;
                let [i0, i1, i2, i3, i4] =
                    [t % 5, (t + 1) % 5, (t + 2) % 5, (t + 3) % 5, (t + 4) % 5];
                h[i0] = h[i0]
                    .wrapping_add(func[i](h[i1], h[i2], h[i3]))
                    .wrapping_add(self.block[idx[i][j]])
                    .wrapping_add(adds[i]);
                h[i0] = h[i0].rotate_left(shifts[i][j]).wrapping_add(h[i4]);
                h[i2] = h[i2].rotate_left(10);
            }
        }

        let mut k = self.state;
        for i in 5..10 {
            for j in 0..16 {
                let t = (20 - (j as i32) + 5 - (i as i32)) as usize;
                let [i0, i1, i2, i3, i4] =
                    [t % 5, (t + 1) % 5, (t + 2) % 5, (t + 3) % 5, (t + 4) % 5];
                k[i0] = k[i0]
                    .wrapping_add(func[i](k[i1], k[i2], k[i3]))
                    .wrapping_add(self.block[idx[i][j]])
                    .wrapping_add(adds[i]);
                k[i0] = k[i0].rotate_left(shifts[i][j]).wrapping_add(k[i4]);
                k[i2] = k[i2].rotate_left(10);
            }
        }

        k[3] = k[3].wrapping_add(self.state[1]).wrapping_add(h[2]);
        self.state[1] = self.state[2].wrapping_add(h[3]).wrapping_add(k[4]);
        self.state[2] = self.state[3].wrapping_add(h[4]).wrapping_add(k[0]);
        self.state[3] = self.state[4].wrapping_add(h[0]).wrapping_add(k[1]);
        self.state[4] = self.state[0].wrapping_add(h[1]).wrapping_add(k[2]);
        self.state[0] = k[3];
    }

    pub fn finalize(&mut self) -> [u8; 20] {
        let pad = super::ripemd160::padding(self.size);
        self.update(&pad);

        let mut digest = [0u8; 20];
        let mut j = 0;
        for i in 0..5 {
            [digest[j], digest[j + 1], digest[j + 2], digest[j + 3]] = self.state[i].to_le_bytes();
            j += 4;
        }

        digest
    }
}

/// Compute ripemd160 hash
/// ```
/// use fractus::hash::ripemd160;
/// assert_eq!(&ripemd160::compute(b"abc"), b"\x8e\xb2\x08\xf7\xe0]\x98z\x9b\x04J\x8e\x98\xc6\xb0\x87\xf1Z\x0b\xfc");
/// ```
pub fn compute(data: impl AsRef<[u8]>) -> [u8; 20] {
    let mut m = Ripemd160::new();
    m.update(data.as_ref());
    m.finalize()
}

/// Compute ripemd160 length extension attack
/// ```
/// use fractus::hash::ripemd160;
/// let secret = b"abc";
/// let hash = ripemd160::compute(&secret);
/// let added_msg = b"cde";
/// let ext = ripemd160::extend(&hash, secret.len(), added_msg);
/// let pad = ripemd160::padding(secret.len());
/// let mut combined = secret.to_vec();
/// combined.extend(pad);
/// combined.extend(added_msg);
/// let combined_hash = ripemd160::compute(combined);
/// assert_eq!(combined_hash, ext);
/// ```
pub fn extend(
    original_hash: &[u8; 20],
    original_size: usize,
    extended_data: impl AsRef<[u8]>,
) -> [u8; 20] {
    let mut m = Ripemd160::from(original_hash);

    let pad_length: usize = padding_len(original_size);
    m.size = original_size + pad_length;

    m.update(extended_data);
    m.finalize()
}

/// Compute ripemd160 padding length for the hashed data length
pub fn padding_len(data_len: usize) -> usize {
    let offset = (data_len % 64) as usize;
    if offset < 56 {
        64 - offset
    } else {
        128 - offset
    }
}

/// Compute ripemd160 padding for the given length
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
    use crate::hash::ripemd160;

    fn from_hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect::<Vec<u8>>()
    }

    #[test]
    fn hash() {
        let expected = [
            (0, "9c1185a5c5e9fc54612808977ee8f548b2258d31"),
            (1, "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe"),
            (2, "fc596101aa50c992c88f53a497fe4feafa8677dd"),
            (127, "64f2d68b85f394e2e4f49009c4bd50224c2698ed"),
            (128, "8dfdfb32b2ed5cb41a73478b4fd60cc5b4648b15"),
            (129, "62bb9091f499f294f15aa5b951df4d9744d50cf2"),
            (10000, "eb33e86b2400cc0a11707be717a35a9acf074a58"),
        ]
        .map(|x| (x.0, from_hex(x.1)));
        for (i, hash) in expected {
            assert_eq!(&hash, &ripemd160::compute(b"a".repeat(i)));
        }
    }

    #[test]
    fn extend() {
        for i in 0..100 {
            for j in 0..100 {
                let secret = b"b".repeat(i);
                let hash = ripemd160::compute(&secret);
                let added_msg = b"c".repeat(j);
                let ext = ripemd160::extend(&hash, secret.len(), &added_msg);
                let pad = ripemd160::padding(secret.len());
                let mut combined = secret.clone();
                combined.extend(pad);
                combined.extend(&added_msg);
                let combined_hash = ripemd160::compute(combined);
                assert_eq!(combined_hash, ext);
            }
        }
    }
}
