#[derive(Clone)]
pub struct Sha1 {
    state: [u32; 5],
    block: [u32; 16],
    size: usize,
}

impl Sha1 {
    pub const IV: [u32; 5] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];
    pub const K: [u32; 4] = [0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6];

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
                .map(|i| u32::from_be_bytes([hash[i], hash[i + 1], hash[i + 2], hash[i + 3]])),
            block: [0; 16],
            size: 0,
        }
    }

    pub fn update(&mut self, input_buf: impl AsRef<[u8]>) -> () {
        let mut offset: usize = self.size % 64;
        self.size += input_buf.as_ref().len();

        for &v in input_buf.as_ref() {
            if offset % 4 == 0 {
                self.block[offset >> 2] = (v as u32) << 24;
            } else {
                self.block[offset >> 2] |= (v as u32) << ((3 - (offset & 3)) << 3);
            }
            offset += 1;

            if offset % 64 == 0 {
                self.transform();
                offset = 0;
            }
        }
    }

    fn transform(&mut self) {
        let mut w = [0u32; 80];
        for i in 0..80 {
            if i < 16 {
                w[i] = self.block[i];
            } else {
                w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
            }
        }

        let mut h = self.state;
        for i in 0..80 {
            let (f, j) = match i {
                0..=19 => ((h[1] & h[2]) | ((!h[1]) & h[3]), 0),
                20..=39 => (h[1] ^ h[2] ^ h[3], 1),
                40..=59 => ((h[1] & h[2]) | (h[1] & h[3]) | (h[2] & h[3]), 2),
                _ => (h[1] ^ h[2] ^ h[3], 3),
            };

            let v = h[0]
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(h[4])
                .wrapping_add(w[i])
                .wrapping_add(Self::K[j]);

            h[4] = h[3];
            h[3] = h[2];
            h[2] = h[1].rotate_left(30);
            h[1] = h[0];
            h[0] = v;
        }
        self.state = [0, 1, 2, 3, 4].map(|i| self.state[i].wrapping_add(h[i]));
    }

    pub fn finalize(&mut self) -> [u8; 20] {
        let pad = super::sha1::padding(self.size);
        self.update(&pad);

        let mut digest = [0u8; 20];
        let mut j = 0;
        for i in 0..5 {
            [digest[j], digest[j + 1], digest[j + 2], digest[j + 3]] = self.state[i].to_be_bytes();
            j += 4;
        }

        digest
    }
}

/// Compute sha1 hash
/// ```
/// use fractus::hash::sha1;
/// assert_eq!(&sha1::compute(b"abc"), b"\xa9\x99>6G\x06\x81j\xba>%qxP\xc2l\x9c\xd0\xd8\x9d");
/// ```
pub fn compute(data: impl AsRef<[u8]>) -> [u8; 20] {
    let mut m = Sha1::new();
    m.update(data.as_ref());
    m.finalize()
}

/// Compute sha1 length extension attack
/// ```
/// use fractus::hash::sha1;
/// let secret = b"abc";
/// let hash = sha1::compute(&secret);
/// let added_msg = b"cde";
/// let ext = sha1::extend(&hash, secret.len(), added_msg);
/// let pad = sha1::padding(secret.len());
/// let mut combined = secret.to_vec();
/// combined.extend(pad);
/// combined.extend(added_msg);
/// let combined_hash = sha1::compute(combined);
/// assert_eq!(combined_hash, ext);
/// ```
pub fn extend(
    original_hash: &[u8; 20],
    original_size: usize,
    extended_data: impl AsRef<[u8]>,
) -> [u8; 20] {
    let mut m = Sha1::from(&original_hash);

    let pad_length: usize = padding_len(original_size);
    m.size = original_size + pad_length;

    m.update(extended_data);
    m.finalize()
}

/// Compute sha1 padding length for the hashed data length
pub fn padding_len(data_len: usize) -> usize {
    let offset = (data_len % 64) as usize;
    if offset < 56 {
        64 - offset
    } else {
        128 - offset
    }
}

/// Compute sha1 padding for the given length
pub fn padding(data_len: usize) -> Vec<u8> {
    let bit_len = data_len.wrapping_mul(8);
    let pad_length: usize = padding_len(data_len);

    let mut pad = vec![0; pad_length];
    pad[0] = 0x80;
    let p: [u8; 8] = bit_len.to_le_bytes();
    for i in 0..8 {
        pad[pad_length - i - 1] = p[i];
    }
    pad
}

#[cfg(test)]
mod test {
    use crate::hash::sha1;

    fn from_hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect::<Vec<u8>>()
    }

    #[test]
    fn hash() {
        let expected = [
            (0, "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
            (1, "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8"),
            (2, "e0c9035898dd52fc65c41454cec9c4d2611bfb37"),
            (127, "89d95fa32ed44a7c610b7ee38517ddf57e0bb975"),
            (128, "ad5b3fdbcb526778c2839d2f151ea753995e26a0"),
            (129, "d96debf1bdcbc896e6c134ea76e8141f40d78536"),
            (10000, "a080cbda64850abb7b7f67ee875ba068074ff6fe"),
        ]
        .map(|x| (x.0, from_hex(x.1)));
        for (i, hash) in expected {
            assert_eq!(&hash, &sha1::compute(b"a".repeat(i)));
        }
    }

    #[test]
    fn extend() {
        for i in 0..130 {
            for j in 0..130 {
                let secret = b"b".repeat(i);
                let hash = sha1::compute(&secret);
                let added_msg = b"c".repeat(j);
                let ext = sha1::extend(&hash, secret.len(), &added_msg);
                let pad = sha1::padding(secret.len());
                let mut combined = secret.clone();
                combined.extend(pad);
                combined.extend(&added_msg);
                let combined_hash = sha1::compute(combined);
                assert_eq!(combined_hash, ext);
            }
        }
    }
}
