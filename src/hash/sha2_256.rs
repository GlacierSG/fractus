#[derive(Clone)]
pub struct Sha2_256 {
    state: [u32; 8],
    block: [u32; 16],
    size: usize,
}

impl Sha2_256 {
    pub const IV: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    pub const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
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
                let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
                let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
                w[i] = s1
                    .wrapping_add(w[i - 7])
                    .wrapping_add(s0)
                    .wrapping_add(w[i - 16]);
            }
        }

        let mut h = self.state;
        for i in 0..64 {
            let s1 = h[4].rotate_right(6) ^ h[4].rotate_right(11) ^ (h[4].rotate_right(25));
            let ch = (h[4] & h[5]) ^ ((!h[4]) & h[6]);

            let v1 = h[7]
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(Self::K[i])
                .wrapping_add(w[i]);

            let s0 = h[0].rotate_right(2) ^ h[0].rotate_right(13) ^ h[0].rotate_right(22);
            let maj = (h[0] & h[1]) ^ (h[0] & h[2]) ^ (h[1] & h[2]);
            let v2 = s0.wrapping_add(maj);

            h[7] = h[6];
            h[6] = h[5];
            h[5] = h[4];
            h[4] = h[3].wrapping_add(v1);
            h[3] = h[2];
            h[2] = h[1];
            h[1] = h[0];
            h[0] = v1.wrapping_add(v2);
        }
        self.state = [0, 1, 2, 3, 4, 5, 6, 7].map(|i| self.state[i].wrapping_add(h[i]));
    }

    pub fn finalize(&mut self) -> [u8; 32] {
        let pad = super::sha1::padding(self.size);
        self.update(&pad);

        let mut digest = [0u8; 32];
        let mut j = 0;
        for i in 0..8 {
            [digest[j], digest[j + 1], digest[j + 2], digest[j + 3]] = self.state[i].to_be_bytes();
            j += 4;
        }

        digest
    }
}

/// Compute Sha2_256 hash
/// ```
/// use fractus::hash::sha2_256;
/// assert_eq!(&sha2_256::compute(b"abc"), b"\xbax\x16\xbf\x8f\x01\xcf\xeaAA@\xde]\xae\"#\xb0\x03a\xa3\x96\x17z\x9c\xb4\x10\xffa\xf2\x00\x15\xad");
/// ```
pub fn compute(data: impl AsRef<[u8]>) -> [u8; 32] {
    let mut m = Sha2_256::new();
    m.update(data.as_ref());
    m.finalize()
}

/// Compute sha2_256 length extension attack
/// ```
/// use fractus::hash::sha2_256;
/// let secret = b"abc";
/// let hash = sha2_256::compute(&secret);
/// let added_msg = b"cde";
/// let ext = sha2_256::extend(&hash, secret.len(), added_msg);
/// let pad = sha2_256::padding(secret.len());
/// let mut combined = secret.to_vec();
/// combined.extend(pad);
/// combined.extend(added_msg);
/// let combined_hash = sha2_256::compute(combined);
/// assert_eq!(combined_hash, ext);
/// ```
pub fn extend(
    original_hash: &[u8; 32],
    original_size: usize,
    extended_data: impl AsRef<[u8]>,
) -> [u8; 32] {
    let mut m = Sha2_256::from(&original_hash);

    let pad_length: usize = padding_len(original_size);
    m.size = original_size + pad_length;

    m.update(extended_data);
    m.finalize()
}

/// Compute sha2_256 padding length for the hashed data length
pub fn padding_len(data_len: usize) -> usize {
    let offset = (data_len % 64) as usize;
    if offset < 56 {
        64 - offset
    } else {
        128 - offset
    }
}

/// Compute sha2_256 padding for the given length
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
    use crate::hash::sha2_256;

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
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            (
                1,
                "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
            ),
            (
                2,
                "961b6dd3ede3cb8ecbaacbd68de040cd78eb2ed5889130cceb4c49268ea4d506",
            ),
            (
                127,
                "c57e9278af78fa3cab38667bef4ce29d783787a2f731d4e12200270f0c32320a",
            ),
            (
                128,
                "6836cf13bac400e9105071cd6af47084dfacad4e5e302c94bfed24e013afb73e",
            ),
            (
                129,
                "c12cb024a2e5551cca0e08fce8f1c5e314555cc3fef6329ee994a3db752166ae",
            ),
            (
                10000,
                "27dd1f61b867b6a0f6e9d8a41c43231de52107e53ae424de8f847b821db4b711",
            ),
        ]
        .map(|x| (x.0, from_hex(x.1)));
        for (i, hash) in expected {
            assert_eq!(&hash, &sha2_256::compute(b"a".repeat(i)));
        }
    }

    #[test]
    fn extend() {
        for i in 0..130 {
            for j in 0..130 {
                let secret = b"b".repeat(i);
                let hash = sha2_256::compute(&secret);
                let added_msg = b"c".repeat(j);
                let ext = sha2_256::extend(&hash, secret.len(), &added_msg);
                let pad = sha2_256::padding(secret.len());
                let mut combined = secret.clone();
                combined.extend(pad);
                combined.extend(&added_msg);
                let combined_hash = sha2_256::compute(combined);
                assert_eq!(combined_hash, ext);
            }
        }
    }
}
