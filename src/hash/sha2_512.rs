#[derive(Clone)]
pub struct Sha2_512 {
    state: [u64; 8],
    block: [u64; 16],
    size: usize,
}

impl Sha2_512 {
    pub const IV: [u64; 8] = [
        0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
        0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
    ];
    pub const K: [u64; 80] = [
        0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
        0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
        0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
        0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
        0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
        0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
        0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
        0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
        0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
        0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
        0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
        0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
        0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
        0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
        0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
        0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
        0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
        0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
        0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
    ];

    pub fn new() -> Self {
        Self {
            state: Self::IV,
            block: [0; 16],
            size: 0,
        }
    }

    pub fn from(hash: &[u8; 64]) -> Self {
        Self {
            state: [0, 8, 16, 24, 32, 40, 48, 56].map(|i| {
                u64::from_be_bytes([
                    hash[i],
                    hash[i + 1],
                    hash[i + 2],
                    hash[i + 3],
                    hash[i + 4],
                    hash[i + 5],
                    hash[i + 6],
                    hash[i + 7],
                ])
            }),
            block: [0; 16],
            size: 0,
        }
    }

    pub fn update(&mut self, input_buf: impl AsRef<[u8]>) -> () {
        let mut offset: usize = self.size % 128;
        self.size += input_buf.as_ref().len();

        for &v in input_buf.as_ref() {
            if offset % 8 == 0 {
                self.block[offset >> 3] = (v as u64) << 56;
            } else {
                self.block[offset >> 3] |= (v as u64) << ((7 - (offset & 7)) << 3);
            }
            offset += 1;

            if offset % 128 == 0 {
                self.transform();
                offset = 0;
            }
        }
    }

    fn transform(&mut self) {
        let mut w = [0u64; 80];
        for i in 0..80 {
            if i < 16 {
                w[i] = self.block[i];
            } else {
                let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
                let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
                w[i] = s1
                    .wrapping_add(w[i - 7])
                    .wrapping_add(s0)
                    .wrapping_add(w[i - 16]);
            }
        }

        let mut h = self.state;
        for i in 0..80 {
            let s1 = h[4].rotate_right(14) ^ h[4].rotate_right(18) ^ (h[4].rotate_right(41));
            let ch = (h[4] & h[5]) ^ ((!h[4]) & h[6]);

            let v1 = h[7]
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(Self::K[i])
                .wrapping_add(w[i]);

            let s0 = h[0].rotate_right(28) ^ h[0].rotate_right(34) ^ h[0].rotate_right(39);
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

    pub fn finalize(&mut self) -> [u8; 64] {
        let pad = super::sha2_512::padding(self.size);
        self.update(&pad);

        let mut digest = [0u8; 64];
        let mut j = 0;
        for i in 0..8 {
            [
                digest[j],
                digest[j + 1],
                digest[j + 2],
                digest[j + 3],
                digest[j + 4],
                digest[j + 5],
                digest[j + 6],
                digest[j + 7],
            ] = self.state[i].to_be_bytes();
            j += 8;
        }

        digest
    }
}

/// Compute Sha2_512 hash
/// ```
/// use fractus::hash::sha2_512;
/// assert_eq!(&sha2_512::compute(b"abc"), b"\xdd\xaf5\xa1\x93az\xba\xccAsI\xae A1\x12\xe6\xfaN\x89\xa9~\xa2\n\x9e\xee\xe6KU\xd3\x9a!\x92\x99*'O\xc1\xa86\xba<#\xa3\xfe\xeb\xbdEMD#d<\xe8\x0e*\x9a\xc9O\xa5L\xa4\x9f");
/// ```
pub fn compute(data: impl AsRef<[u8]>) -> [u8; 64] {
    let mut m = Sha2_512::new();
    m.update(data.as_ref());
    m.finalize()
}

/// Compute sha2_512 length extension attack
/// ```
/// use fractus::hash::sha2_512;
/// let secret = b"abc";
/// let hash = sha2_512::compute(&secret);
/// let added_msg = b"cde";
/// let ext = sha2_512::extend(&hash, secret.len(), added_msg);
/// let pad = sha2_512::padding(secret.len());
/// let mut combined = secret.to_vec();
/// combined.extend(pad);
/// combined.extend(added_msg);
/// let combined_hash = sha2_512::compute(combined);
/// assert_eq!(combined_hash, ext);
/// ```
pub fn extend(
    original_hash: &[u8; 64],
    original_size: usize,
    extended_data: impl AsRef<[u8]>,
) -> [u8; 64] {
    let mut m = Sha2_512::from(&original_hash);

    let pad_length: usize = padding_len(original_size);
    m.size = original_size + pad_length;

    m.update(extended_data);
    m.finalize()
}

/// Compute sha2_512 padding length for the hashed data length
pub fn padding_len(data_len: usize) -> usize {
    let offset = (data_len % 128) as usize;
    if offset < 112 {
        128 - offset
    } else {
        256 - offset
    }
}

/// Compute sha2_512 padding for the given length
pub fn padding(data_len: usize) -> Vec<u8> {
    let bit_len = data_len.wrapping_mul(8);
    let pad_length: usize = padding_len(data_len);

    let mut pad = vec![0; pad_length];
    pad[0] = 0x80;
    let p: [u8; 16] = (bit_len as u128).to_le_bytes();
    for i in 0..16 {
        pad[pad_length - i - 1] = p[i];
    }
    pad
}

#[cfg(test)]
mod test {
    use crate::hash::sha2_512;

    fn from_hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect::<Vec<u8>>()
    }

    #[test]
    fn hash() {
        let expected = [
            (0, "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"),
            (1, "1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75"),
            (2, "f6c5600ed1dbdcfdf829081f5417dccbbd2b9288e0b427e65c8cf67e274b69009cd142475e15304f599f429f260a661b5df4de26746459a3cef7f32006e5d1c1"),
            (127, "828613968b501dc00a97e08c73b118aa8876c26b8aac93df128502ab360f91bab50a51e088769a5c1eff4782ace147dce3642554199876374291f5d921629502"),
            (128, "b73d1929aa615934e61a871596b3f3b33359f42b8175602e89f7e06e5f658a243667807ed300314b95cacdd579f3e33abdfbe351909519a846d465c59582f321"),
            (129, "4f681e0bd53cda4b5a2041cc8a06f2eabde44fb16c951fbd5b87702f07aeab611565b19c47fde30587177ebb852e3971bbd8d3fd30da18d71037dfbd98420429"),
            (10000, "0593036f4f479d2eb8078ca26b1d59321a86bdfcb04cb40043694f1eb0301b8acd20b936db3c916ebcc1b609400ffcf3fa8d569d7e39293855668645094baf0e"),
        ]
        .map(|x| (x.0, from_hex(x.1)));
        for (i, hash) in expected {
            assert_eq!(&hash, &sha2_512::compute(b"a".repeat(i)));
        }
    }

    #[test]
    fn extend() {
        for i in 0..130 {
            for j in 0..130 {
                let secret = b"b".repeat(i);
                let hash = sha2_512::compute(&secret);
                let added_msg = b"c".repeat(j);
                let ext = sha2_512::extend(&hash, secret.len(), &added_msg);
                let pad = sha2_512::padding(secret.len());
                let mut combined = secret.clone();
                combined.extend(pad);
                combined.extend(&added_msg);
                let combined_hash = sha2_512::compute(combined);
                assert_eq!(combined_hash, ext);
            }
        }
    }
}
