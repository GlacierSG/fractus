#[derive(Clone)]
pub struct Md5 {
    state: [u32; 4],
    block: [u32; 16],
    size: usize,
}

impl Md5 {
    pub const IV: [u32; 4] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];
    pub const S: [u8; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    pub const K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
        0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
        0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
        0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
        0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
        0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
        0xeb86d391,
    ];

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

    fn transform(&mut self) {
        let [mut a, mut b, mut c, mut d] = self.state;
        for i in 0..64 {
            let (e, j) = match i {
                0..=15 => ((b & c) | (!b & d), i),
                16..=31 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let v = a
                .wrapping_add(e)
                .wrapping_add(Self::K[i])
                .wrapping_add(self.block[j]);

            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(v.rotate_left(Self::S[i] as u32));
        }
        self.state = [0, 1, 2, 3].map(|i| self.state[i].wrapping_add([a, b, c, d][i]));
    }

    pub fn finalize(&mut self) -> [u8; 16] {
        let pad = super::md5::padding(self.size);

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

/// Compute md5 hash
/// ```
/// use fractus::hash::md5;
/// assert_eq!(&md5::compute(b"abc"), b"\x90\x01P\x98<\xd2O\xb0\xd6\x96?}(\xe1\x7fr");
/// ```
pub fn compute(data: impl AsRef<[u8]>) -> [u8; 16] {
    let mut m = Md5::new();
    m.update(data.as_ref());
    m.finalize()
}

/// Compute md5 length extension attack
/// ```
/// use fractus::hash::md5;
/// let secret = b"abc";
/// let hash = md5::compute(&secret);
/// let added_msg = b"cde";
/// let ext = md5::extend(&hash, secret.len(), added_msg);
/// let pad = md5::padding(secret.len());
/// let mut combined = secret.to_vec();
/// combined.extend(pad);
/// combined.extend(added_msg);
/// let combined_hash = md5::compute(combined);
/// assert_eq!(combined_hash, ext);
/// ```
pub fn extend(
    original_hash: &[u8; 16],
    original_size: usize,
    extended_data: impl AsRef<[u8]>,
) -> [u8; 16] {
    let mut m = Md5::from(&original_hash);

    let pad_length: usize = padding_len(original_size);
    m.size = original_size + pad_length;

    m.update(extended_data);
    m.finalize()
}

/// Compute md5 padding length for the hashed data length
pub fn padding_len(data_len: usize) -> usize {
    let offset = (data_len % 64) as usize;
    if offset < 56 {
        64 - offset
    } else {
        128 - offset
    }
}

/// Compute md5 padding for the given length
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
    use crate::hash::md5;

    fn from_hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect::<Vec<u8>>()
    }

    #[test]
    fn hash() {
        let expected = [
            (0, "d41d8cd98f00b204e9800998ecf8427e"),
            (1, "0cc175b9c0f1b6a831c399e269772661"),
            (2, "4124bc0a9335c27f086f24ba207a4912"),
            (127, "020406e1d05cdc2aa287641f7ae2cc39"),
            (128, "e510683b3f5ffe4093d021808bc6ff70"),
            (129, "b325dc1c6f5e7a2b7cf465b9feab7948"),
            (10000, "0d0c9c4db6953fee9e03f528cafd7d3e"),
        ]
        .map(|x| (x.0, from_hex(x.1)));
        for (i, hash) in expected {
            assert_eq!(&hash, &md5::compute(b"a".repeat(i)));
        }
    }

    #[test]
    fn extend() {
        for i in 0..130 {
            for j in 0..130 {
                let secret = b"b".repeat(i);
                let hash = md5::compute(&secret);
                let added_msg = b"c".repeat(j);
                let ext = md5::extend(&hash, secret.len(), &added_msg);
                let pad = md5::padding(secret.len());
                let mut combined = secret.clone();
                combined.extend(pad);
                combined.extend(&added_msg);
                let combined_hash = md5::compute(combined);
                assert_eq!(combined_hash, ext);
            }
        }
    }
}
