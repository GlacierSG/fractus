#[derive(Clone)]
pub struct Md4 {
    state: [u32; 4],
    block: [u32; 16],
    size: usize,
}

impl Md4 {
    pub const IV: [u32; 4] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];

    pub fn new() -> Self {
        Self {
            state: Self::IV,
            block: [0; 16],
            size: 0,
        }
    }

    pub fn from(hash: &[u8; 16]) -> Self {
        Self {
            state: [0, 4, 8, 12]
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

    fn f(x: u32, y: u32, z: u32) -> u32 {
        (x & y) | ((!x) & z)
    }
    fn g(x: u32, y: u32, z: u32) -> u32 {
        (x & y) | (x & z) | (y & z)
    }
    fn h(x: u32, y: u32, z: u32) -> u32 {
        x ^ y ^ z
    }

    fn round1(a: u32, b: u32, c: u32, d: u32, x: u32, s: u32) -> u32 {
        a.wrapping_add(Self::f(b, c, d))
            .wrapping_add(x)
            .rotate_left(s)
    }

    fn round2(a: u32, b: u32, c: u32, d: u32, x: u32, s: u32) -> u32 {
        a.wrapping_add(Self::g(b, c, d))
            .wrapping_add(x)
            .wrapping_add(0x5a827999)
            .rotate_left(s)
    }

    fn round3(a: u32, b: u32, c: u32, d: u32, x: u32, s: u32) -> u32 {
        a.wrapping_add(Self::h(b, c, d))
            .wrapping_add(x)
            .wrapping_add(0x6ed9eba1)
            .rotate_left(s)
    }

    fn transform(&mut self) {
        let [mut a, mut b, mut c, mut d] = self.state;

        let x = self.block;

        let s1 = [3, 7, 11, 19];

        for i in [0, 4, 8, 12] {
            a = Self::round1(a, b, c, d, x[i], s1[0]);
            d = Self::round1(d, a, b, c, x[i + 1], s1[1]);
            c = Self::round1(c, d, a, b, x[i + 2], s1[2]);
            b = Self::round1(b, c, d, a, x[i + 3], s1[3]);
        }

        let s2 = [3, 5, 9, 13];
        for i in 0..4 {
            a = Self::round2(a, b, c, d, x[i], s2[0]);
            d = Self::round2(d, a, b, c, x[i + 4], s2[1]);
            c = Self::round2(c, d, a, b, x[i + 8], s2[2]);
            b = Self::round2(b, c, d, a, x[i + 12], s2[3]);
        }

        let idx = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15];
        let s3 = [3, 9, 11, 15];
        for i in [0, 4, 8, 12] {
            a = Self::round3(a, b, c, d, x[idx[i]], s3[0]);
            d = Self::round3(d, a, b, c, x[idx[i + 1]], s3[1]);
            c = Self::round3(c, d, a, b, x[idx[i + 2]], s3[2]);
            b = Self::round3(b, c, d, a, x[idx[i + 3]], s3[3]);
        }

        self.state = [0, 1, 2, 3].map(|i| self.state[i].wrapping_add([a, b, c, d][i]));
    }

    pub fn finalize(&mut self) -> [u8; 16] {
        let pad = super::md4::padding(self.size);

        self.update(&pad);

        let mut digest = [0u8; 16];
        let mut j = 0;
        for i in 0..4 {
            [digest[j], digest[j + 1], digest[j + 2], digest[j + 3]] = self.state[i].to_le_bytes();
            j += 4;
        }

        digest
    }
}

/// Compute md4 hash
/// ```
/// use fractus::hash::md4;
/// assert_eq!(&md4::compute(b"abc"), b"\xa4H\x01z\xaf!\xd8R_\xc1\n\xe8z\xa6r\x9d");
/// ```
pub fn compute(data: impl AsRef<[u8]>) -> [u8; 16] {
    let mut m = Md4::new();
    m.update(data.as_ref());
    m.finalize()
}

/// Compute md4 length extension attack
/// ```
/// use fractus::hash::md4;
/// let secret = b"abc";
/// let hash = md4::compute(&secret);
/// let added_msg = b"cde";
/// let ext = md4::extend(&hash, secret.len(), added_msg);
/// let pad = md4::padding(secret.len());
/// let mut combined = secret.to_vec();
/// combined.extend(pad);
/// combined.extend(added_msg);
/// let combined_hash = md4::compute(combined);
/// assert_eq!(combined_hash, ext);
/// ```
pub fn extend(
    original_hash: &[u8; 16],
    original_size: usize,
    extended_data: impl AsRef<[u8]>,
) -> [u8; 16] {
    let mut m = Md4::from(&original_hash);

    let pad_length: usize = padding_len(original_size);
    m.size = original_size + pad_length;

    m.update(extended_data);
    m.finalize()
}

/// Compute md4 padding length for the hashed data length
pub fn padding_len(data_len: usize) -> usize {
    let offset = (data_len % 64) as usize;
    if offset < 56 {
        64 - offset
    } else {
        128 - offset
    }
}

/// Compute md4 padding for the given length
pub fn padding(data_len: usize) -> Vec<u8> {
    let bit_len = data_len.wrapping_mul(8);
    let pad_length: usize = padding_len(data_len);

    let mut pad = vec![0; pad_length];
    pad[0] = 0x80;
    let p: [u8; 8] = bit_len.to_le_bytes();
    for i in 0..8 {
        pad[pad_length - 8 + i] = p[i];
    }
    pad
}

#[cfg(test)]
mod test {
    use crate::hash::md4;

    fn from_hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect::<Vec<u8>>()
    }

    #[test]
    fn hash() {
        let expected = [
            (0, "31d6cfe0d16ae931b73c59d7e0c089c0"),
            (1, "bde52cb31de33e46245e05fbdbd6fb24"),
            (2, "0de97e6bacb92b24d7578ffb8d58f51e"),
            (127, "9733b046ad770b4e093b35de4e09e828"),
            (128, "cb4a20a561558e29460190c91dced59f"),
            (129, "2adcd303c29f93a3ee33a560ece91cd2"),
            (10000, "9c88157a6f588e9815a9e6b60877d93e"),
        ]
        .map(|x| (x.0, from_hex(x.1)));
        for (i, hash) in expected {
            assert_eq!(&hash, &md4::compute(b"a".repeat(i)));
        }
    }

    #[test]
    fn extend() {
        for i in 0..130 {
            for j in 0..130 {
                let secret = b"b".repeat(i);
                let hash = md4::compute(&secret);
                let added_msg = b"c".repeat(j);
                let ext = md4::extend(&hash, secret.len(), &added_msg);
                let pad = md4::padding(secret.len());
                let mut combined = secret.clone();
                combined.extend(pad);
                combined.extend(&added_msg);
                let combined_hash = md4::compute(combined);
                assert_eq!(combined_hash, ext);
            }
        }
    }
}
