#[derive(Clone, Debug)]
pub struct Keccak {
    pub state: [u64; 25],
    pub bitrate: usize,
    pub width: usize,
    pub size: usize,
    pub d: u8
}

pub fn index(mut x: usize, mut y: usize) -> usize {
    if x >= 5 { x %= 5; }
    if y >= 5 { y %= 5; }

    x + y*5
}

impl Keccak {
    pub const ROUND: [u64; 24] = [
        0x0000000000000001,
        0x0000000000008082,
        0x800000000000808A,
        0x8000000080008000,
        0x000000000000808B,
        0x0000000080000001,
        0x8000000080008081,
        0x8000000000008009,
        0x000000000000008A,
        0x0000000000000088,
        0x0000000080008009,
        0x000000008000000A,
        0x000000008000808B,
        0x800000000000008B,
        0x8000000000008089,
        0x8000000000008003,
        0x8000000000008002,
        0x8000000000000080,
        0x000000000000800A,
        0x800000008000000A,
        0x8000000080008081,
        0x8000000000008080,
        0x0000000080000001,
        0x8000000080008008,
    ];
    pub const ROTATION: [u32; 25] = [
        0,  1, 62, 28, 27,
       36, 44,  6, 55, 20,
        3, 10, 43, 25, 39,
       41, 45, 15, 21,  8,
       18,  2, 61, 56, 14,
    ];

    pub fn new(bitrate: usize, width: usize) -> Keccak {
        Keccak {
            state: [0; 25],
            bitrate,
            width,
            size: 0,
            d: 0x01
        }
    }

    pub fn padding(&self, data_len: usize) -> Vec<u8> {
        let rate = self.bitrate >> 3;
        let mut pad_len = (rate - (data_len % rate)) % rate;
        if pad_len == 0 {
            pad_len = rate;
        }
        if pad_len == 1 {
            return vec![0x81];
        }
        else {
            let mut padding = vec![self.d];
            padding.extend(vec![0x00].repeat(pad_len-2));
            padding.push(0x80);
            return padding;
        }
    }
    
    pub fn capacity(&self) -> usize {
        self.width - self.bitrate
    }

    pub fn theta(&mut self) {
        let mut xor_vec = vec![0; 5];
        for x in 0..5 {
            xor_vec[x] = self.state[index(x,0)];
            for y in 1..5 {
                xor_vec[x] ^= self.state[index(x,y)];
            }
        }
        for x in 0..5 {
            let dx = xor_vec[(x + 4) % 5] ^ xor_vec[(x + 1) % 5].rotate_left(1);
            for y in 0..5 {
                self.state[index(x,y)] ^= dx;
            }
        }
    }

    pub fn theta_inv(&mut self) {
        let mut tmp = [0; 5];
        for x in 0..5 {
            tmp[x] = self.state[index(x, 0)];
            for y in 1..5 {
                tmp[x] ^= self.state[index(x,y)];
            }
        }
        let lane_size = self.width/25;
        let mut inv_pos: [u64; 5] = [
            0xde26bc4d789af134,
            0x09af135e26bc4d78,
            0xebc4d789af135e26,
            0x7135e26bc4d789af,
            0xcd789af135e26bc4];

        for _ in 0..lane_size {
            for x_off in 0..5 {
                for x in 0..5 {
                    for y in 0..5 {
                        if inv_pos[x_off] & 1 != 0 {
                            self.state[index(x,y)] ^= tmp[(5+x-x_off) % 5];
                        }
                    }
                }
            }
            for x_off in 0..5 {
                tmp[x_off] = tmp[x_off].rotate_left(1);
                inv_pos[x_off] >>= 1;
            }
        }
    }

    pub fn rho(&mut self) {
        for x in 0..5 {
            for y in 0..5 {
                self.state[index(x,y)] = self.state[index(x,y)].rotate_left(Self::ROTATION[index(x,y)]);
            }
        }
    }
    pub fn rho_inv(&mut self) {
        for x in 0..5 {
            for y in 0..5 {
                self.state[index(x,y)] = self.state[index(x,y)].rotate_right(Self::ROTATION[index(x,y)]);
            }
        }
    }

    pub fn pi(&mut self) {
        let mut new_state = self.state.clone();
        for x in 0..5 {
            for y in 0..5 {
                new_state[index(y, 2*x + 3*y)] = self.state[index(x, y)];
            }
        }
        self.state = new_state;
    }
    pub fn pi_inv(&mut self) {
        let mut new_state = self.state.clone();
        for x in 0..5 {
            for y in 0..5 {
                 new_state[index(x+3*y, x)] = self.state[index(x, y)];
            }
        }
        self.state = new_state;
    }

    pub fn chi(&mut self) {
        let mut tmp = [0; 5];
        for y in 0..5 {
            for x in 0..5 {
                tmp[x] = self.state[index(x,y)] ^ ((!self.state[index(x+1, y)]) & self.state[index(x+2,y)]);
            }
            for x in 0..5 {
                self.state[index(x,y)] = tmp[x];
            }
        }
    }
    pub fn chi_inv(&mut self) {
        for y in 0..5 {
            let mut tmp = [0; 5];
            for x in 0..5 {
                tmp[x] = self.state[index(x,y)];
            }
            for x in 0..6 {
                let tx = 3*x;
                self.state[index(tx,y)] = tmp[tx % 5] ^ (self.state[index(tx+2, y)] & (!tmp[(tx+1) % 5]));
            }
        }
    }

    pub fn iota(&mut self, rc: u64) {
        self.state[0] ^= rc;
    }
    pub fn iota_inv(&mut self, rc: u64) {
        self.state[0] ^= rc;
    }

    pub fn f(&mut self) {
        for rc in Self::ROUND {
            self.theta();
            self.rho();
            self.pi();
            self.chi();
            self.iota(rc);
        }
    }
    pub fn f_inv(&mut self) {
        for rc in Self::ROUND.iter().rev() {
            self.iota_inv(*rc);
            self.chi_inv();
            self.pi_inv();
            self.rho_inv();
            self.theta_inv();
        }
    }
    fn absorb_block(&mut self, block: &[u8]) {
        'for_y: for y in 0..5 {
            for x in 0..5 {
                if (1+index(x, y))<<3 > block.len() { break 'for_y; }
                self.state[index(x, y)] ^= u64::from_le_bytes(block[index(x, y)<<3..(1+index(x, y))<<3].try_into().expect("Incorrect length"));
            }
        }
        self.f();
    }
    pub fn absorb(&mut self, data: impl AsRef<[u8]>) {
        let mut data = data.as_ref().to_vec();
        self.size += data.len();
        data.extend(self.padding(data.len()));
        let rate = self.bitrate >> 3;

        for i in 0..data.len()/rate {
            self.absorb_block(&data[i*rate..(i+1)*rate]);
        }
    }

    fn unabsorb_block(&mut self, block: &[u8]) {
        self.f_inv();
        'for_y: for y in 0..5 {
            for x in 0..5 {
                if (1+index(x, y))<<3 > block.len() { break 'for_y; }
                self.state[index(x, y)] ^= u64::from_le_bytes(block[index(x, y)<<3..(1+index(x, y))<<3].try_into().expect("Incorrect length"));
            }
        }
    }

    pub fn unabsorb(&mut self, data: impl AsRef<[u8]>) {
        let mut data = data.as_ref().to_vec();
        let rem_len = data.len();
        let rate = self.bitrate >> 3;
        data.extend(self.padding(self.size));
        data = if data.len() % rate == 0 {
            data
        }
        else {
            let mut new_data = vec![0].repeat(rate - (data.len() % rate));
            new_data.extend(data);
            new_data
        };

        for i in (0..data.len()/rate).rev() {
            self.unabsorb_block(&data[i*rate..(i+1)*rate]);
        }
        self.size -= rem_len;

        let mut pad = self.padding(self.size);
        pad = if pad.len() % rate == 0 {
            pad
        }
        else {
            let mut new_pad = vec![0].repeat(rate - (pad.len() % rate));
            new_pad.extend(pad);
            new_pad
        };

        self.absorb_block(&pad);

    }

    pub fn squeeze(&mut self) -> Vec<u8> {
        let len = self.capacity()/16;
        let mut out = vec![0u8; len];
        let (mut x, mut y) = (0, 0);
        let rem = if len%8 == 0 { 8 } else { len%8 };
        for i in (0..len-rem).step_by(8) {
            out[i..i+8].copy_from_slice(&self.state[index(x,y)].to_le_bytes());
            (x, y) = if x >= 4 {
                (0, y+1)
            }
            else {
                (x+1, y)
            };
        }
        out[len-rem..len].copy_from_slice(&self.state[index(x,y)].to_le_bytes()[..rem]);
        out
    }
}

pub fn new(bitrate: usize, width: usize) -> Keccak {
    let mut kec = Keccak::new(bitrate, width);
    kec.d = 0x01;
    kec
}

pub fn v224() -> Keccak {
    let bitrate = 1152;
    let capacity = 448;
    let width = bitrate+capacity;
    new(bitrate, width)
}

pub fn v256() -> Keccak {
    let bitrate = 1088;
    let width = 1600;
    new(bitrate, width)
}

pub fn v384() -> Keccak {
    let bitrate = 832;
    let capacity = 768;
    let width = bitrate+capacity;
    new(bitrate, width)
}

pub fn v512() -> Keccak {
    let bitrate = 576;
    let capacity = 1024;
    let width = bitrate+capacity;
    new(bitrate, width)
}

#[cfg(test)]
mod test {
    use crate::keccak;
    use rand::{Rng, SeedableRng};
    use rand::rngs::StdRng;

    #[test]
    fn simple() {
        // keccak 224
        let mut kec = keccak::v224();
        kec.absorb(b"a".repeat(1000));
        assert_eq!(kec.squeeze(), b"\x0c\xfe\x02\xa6\xb3\xc6\x19\xd5\xc0z\xf0\xf5\"\x81 lF\xbf\x11\xc7\x1d\x08\xe0,\x18\xd9\x84\x19");

        let mut rng = StdRng::seed_from_u64(1);
        let mut v = vec![];
        for _ in 0..1337 {
            let random_u8: u8 = rng.gen();
            v.push(random_u8);
        }
        let mut kec = keccak::v224();
        kec.absorb(v);
        assert_eq!(kec.squeeze(), b"O\xbd\x1b;\xc8\x16-\x98\x93r\x04\x80\xe4\xd33\xecB\xfax\xbe\xe1X\xf6\r\x89E\xea\xfd");


        // Keccak 256
        let mut kec = keccak::v256();
        kec.absorb(b"abc");
        assert_eq!(kec.squeeze(), b"N\x03ez\xeaE\xa9O\xc7\xd4{\xa8&\xc8\xd6g\xc0\xd1\xe6\xe3:d\xa06\xecD\xf5\x8f\xa1-lE");
        let mut kec = keccak::v256();
        kec.absorb(b"a".repeat(1000));
        assert_eq!(kec.squeeze(), b"\xb6\xa4\xac\x1fQ\x88Mq\xf3\x0f\xa3\x97\xa5\xe1U\xde0\x99\xe1\x1f\xc0\xed\xef]\x08\xb6F\xe6!\xe1\x9d\xe9");

        let mut rng = StdRng::seed_from_u64(1);
        let mut v = vec![];
        for _ in 0..1337 {
            let random_u8: u8 = rng.gen();
            v.push(random_u8);
        }
        let mut kec = keccak::v256();
        kec.absorb(v);
        assert_eq!(kec.squeeze(), b"\x8bjT\xe32\xc3[\x89\x80\xc4\x93\x9d\xb8\x0e\x91+\xba\xd41\xf8\x99+#\xce \xe9\xa2\x17\xfd+(\xb9");

        // Keccak 384
        let mut kec = keccak::v384();
        kec.absorb(b"abc");
        assert_eq!(kec.squeeze(), b"\xf7\xdf\x11e\xf033{\xe0\x98\xe7\xd2\x88\xadj/t@\x9dz`\xb4\x9c6d\"\x18\xde\x16\x1b\x1f\x99\xf8\xc6\x81\xe4\xaf\xaf1\xa3M\xb2\x9f\xb7c\xe3\xc2\x8e");
        let mut kec = keccak::v384();
        kec.absorb(b"a".repeat(1000));
        assert_eq!(kec.squeeze(), b"\xb3\xe6w\xe39\"\x89\xab\xe0b\xcc\xb9q\x168@\xeaor\x87T\xc7/\x8e?\x80\xad(5\x8cL\xb0\xf8\xa0\xd6\xf3\x99[\xf0\x93I\xfc\xcf\xda\x19\xdb\x0e\xf4");

        let mut rng = StdRng::seed_from_u64(1);
        let mut v = vec![];
        for _ in 0..1337 {
            let random_u8: u8 = rng.gen();
            v.push(random_u8);
        }
        let mut kec = keccak::v384();
        kec.absorb(v);
        assert_eq!(kec.squeeze(), b"\x1cdT\r`P\x14\xed\x9bu\n\x9e!\x0e\xfa\x8b\xed\x83\xf8\xbe?he<\xe1\xf2]2\xd9\x12p\xa8\xf3\x8b\xdd\xeb\x1f\xe2\xc3\xef\xee\x00\xdc\x95A\n5\x8f");


        // keccak 512
        let mut kec = keccak::v512();
        kec.absorb(b"a".repeat(1000));
        assert_eq!(kec.squeeze(), b"\x96;\xcf\xf8\x8a\x13\xa6\xf6_\x89R\xd8\xc1?\xffX{Q\xba\xa5\t\x96q*\x0e\xf6w\x9f\xf1HE\x9f(x\x8e\xe9\xaa\xdaV\x16\x97+\xe9\x03l\x0e\x8d\xec{\xb8\x86\xce\xa3h\xbb\xfd\xe7?\xc5\xf8l2\xa5a");

        let mut rng = StdRng::seed_from_u64(1);
        let mut v = vec![];
        for _ in 0..1337 {
            let random_u8: u8 = rng.gen();
            v.push(random_u8);
        }
        let mut kec = keccak::v512();
        kec.absorb(v);
        assert_eq!(kec.squeeze(), b"\x90\x90m\xca\xed\x94\xec0\xb9A\xbf\xc3\xf8V|\xc0w\xcdV7zf\x01\xfeA\xf9\xc62\xf3Z\xea\xecG\xca\xa2e\x02\x96\xc3A\xca\x85b\x05\x18q\x8a\xf2s\xb9\xb0#\x99\"\xaa@\x0fe\x8at\xf0F\xa0_");
    }
    #[test]
    fn unabsorb() {
        let mut rng = StdRng::seed_from_u64(1);
        for t in 0..10 {
            for m in 0..t {
                let mut v = vec![];
                for _ in 0..t {
                    let random_u8: u8 = rng.gen();
                    v.push(random_u8);
                }
                let mut kec = keccak::v256();
                kec.absorb(&v);
                kec.unabsorb(&v[m..]);
                let mut kec2 = keccak::v256();
                kec2.absorb(&v[..m]);
                assert_eq!(kec.squeeze(), kec2.squeeze());
            }
        }

        // Keccak 224
        let mut v = vec![];
        for _ in 0..1000 {
            let random_u8: u8 = rng.gen();
            v.push(random_u8);
        }
        let mut kec = keccak::v224();
        kec.absorb(&v);
        kec.unabsorb(&v[500..]);
        let mut kec2 = keccak::v224();
        kec2.absorb(&v[..500]);
        assert_eq!(kec.squeeze(), kec2.squeeze());

        // Keccak 256
        let mut v = vec![];
        for _ in 0..1000 {
            let random_u8: u8 = rng.gen();
            v.push(random_u8);
        }
        let mut kec = keccak::v256();
        kec.absorb(&v);
        kec.unabsorb(&v[500..]);
        let mut kec2 = keccak::v256();
        kec2.absorb(&v[..500]);
        assert_eq!(kec.squeeze(), kec2.squeeze());

        // Keccak 384
        let mut v = vec![];
        for _ in 0..1000 {
            let random_u8: u8 = rng.gen();
            v.push(random_u8);
        }
        let mut kec = keccak::v384();
        kec.absorb(&v);
        kec.unabsorb(&v[500..]);
        let mut kec2 = keccak::v384();
        kec2.absorb(&v[..500]);
        assert_eq!(kec.squeeze(), kec2.squeeze());

        // Keccak 512
        let mut v = vec![];
        for _ in 0..1000 {
            let random_u8: u8 = rng.gen();
            v.push(random_u8);
        }
        let mut kec = keccak::v512();
        kec.absorb(&v);
        kec.unabsorb(&v[500..]);
        let mut kec2 = keccak::v512();
        kec2.absorb(&v[..500]);
        assert_eq!(kec.squeeze(), kec2.squeeze());

    }
}
