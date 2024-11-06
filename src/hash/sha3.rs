use super::keccak::Keccak;

pub fn new(bitrate: usize, width: usize) -> Keccak {
    let mut kec = Keccak::new(bitrate, width);
    kec.d = 0x06;
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
    use crate::sha3;
    use rand::{Rng, SeedableRng};
    use rand::rngs::StdRng;

    #[test]
    fn simple() {
        // Sha3 224
        let mut kec = sha3::v224();
        kec.absorb(b"a".repeat(1000));
        assert_eq!(kec.squeeze(), b"$a4K\x84Am\xb8\xfe\x01\xc2\xa4\x96o\xea\x01\x95\x90\xc21\xddW$\xc1\xbf\xc2gE");

        let mut rng = StdRng::seed_from_u64(1);
        let mut v = vec![];
        for _ in 0..1337 {
            let random_u8: u8 = rng.gen();
            v.push(random_u8);
        }
        let mut kec = sha3::v224();
        kec.absorb(v);
        assert_eq!(kec.squeeze(), b"\xd4\xcb\xce\x81\xf0\xf8\xa2\xa3\x82A{\xae!S\xd7.P>\xc5\xb84\x0b\xf6H\x88/\xa0m");


        // Sha3 256
        let mut kec = sha3::v256();
        kec.absorb(b"abc");
        assert_eq!(kec.squeeze(), b":\x98]\xa7O\xe2%\xb2\x04\\\x17-k\xd3\x90\xbd\x85_\x08n>\x9dR[F\xbf\xe2E\x11C\x152");
        let mut kec = sha3::v256();
        kec.absorb(b"a".repeat(1000));
        assert_eq!(kec.squeeze(), b"\x8f94\xe6\xf7\xa1V\x98\xfe\x0f9k\x95\xd8\xc4D\t)\xa8\xfan\xae\x14\x01q\xc0h\xb4T\x9f\xbf\x81");

        let mut rng = StdRng::seed_from_u64(1);
        let mut v = vec![];
        for _ in 0..1337 {
            let random_u8: u8 = rng.gen();
            v.push(random_u8);
        }
        let mut kec = sha3::v256();
        kec.absorb(v);
        assert_eq!(kec.squeeze(), b"7\xe7vu\xf4\xa5\xf61\x1deb\x06\x1c\xec/ov\xc1sD\xff\xb7\x8c\xdb\x1d\x87\xd9\x88\x93\xa8\x98\x1a");

        // Sha3 384
        let mut kec = sha3::v384();
        kec.absorb(b"abc");
        assert_eq!(kec.squeeze(), b"\xec\x01I\x82\x88Qo\xc9&E\x9fX\xe2\xc6\xad\x8d\xf9\xb4s\xcb\x0f\xc0\x8c%\x96\xda|\xf0\xe4\x9b\xe4\xb2\x98\xd8\x8c\xea\x92z\xc7\xf59\xf1\xed\xf2(7m%");
        let mut kec = sha3::v384();
        kec.absorb(b"a".repeat(1000));
        assert_eq!(kec.squeeze(), b"\xcc\xf4I_\xf2\x0bK3\xa1\xcc\x19\x17\xf9\xf0\xfe\x0f\xcb^=\x08\xe5B\xcfMJ\x90\xdd\x95\x0bt\x8e~\x1c\xc0}/;6\xd6-\xd2@rD\x17\xcd\xd8\x1b");

        let mut rng = StdRng::seed_from_u64(1);
        let mut v = vec![];
        for _ in 0..1337 {
            let random_u8: u8 = rng.gen();
            v.push(random_u8);
        }
        let mut kec = sha3::v384();
        kec.absorb(v);
        assert_eq!(kec.squeeze(), b"\x80\xa4\x81\xfc\xb3 \xde:\xce\xcf\xf5\xdc;1\x04nI\xd0\xeek\xbf\x13\x9aJ\x9e2\x16\xc1\x9c\xfeo\"M\xa3\t\x14\xfb##\x00\xf8+l\xfe\xc3\xd8|\xf6");


        // Sha3 512
        let mut kec = sha3::v512();
        kec.absorb(b"a".repeat(1000));
        assert_eq!(kec.squeeze(), b"\xac~\x95\xcc\x95\xaa\x7f$\xaa\xa9^\x04\x0c\xa0\xc7\x9b9\xcd\x9c\xc8J\x10\xab\xb8M\xdd\x8d\xd5\xe4\xb4\\\xf9eC\xaa\xa7\r\x0e\xf9\x9f\xbf\x8d'ic\x99\x81\xee\x1f\xd0\xb0'oGV\xb9\xd5\x04\xd0\xb7\xde\x19\xb7\x00");

        let mut rng = StdRng::seed_from_u64(1);
        let mut v = vec![];
        for _ in 0..1337 {
            let random_u8: u8 = rng.gen();
            v.push(random_u8);
        }
        let mut kec = sha3::v512();
        kec.absorb(v);
        assert_eq!(kec.squeeze(), b"\xcc2I\x155E\x89\xa7\x02@\x86\\_~\x851j\x92x\x10\x81\x94T\xeaQ\xff\x89n\xda\xf7\x87l\xb0ZQ|\xb5\xa7\xd5\x1f\x0c\xc6\xd1\xb0k\xaa\xfeTV\x89\x13\x05o(\x14\xce\xf6\xa4\xb3\xc3\xba\xb3\x06\x9e");
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
                let mut kec = sha3::v256();
                kec.absorb(&v);
                kec.unabsorb(&v[m..]);
                let mut kec2 = sha3::v256();
                kec2.absorb(&v[..m]);
                assert_eq!(kec.squeeze(), kec2.squeeze());
            }
        }

        // Sha3 224
        let mut v = vec![];
        for _ in 0..1000 {
            let random_u8: u8 = rng.gen();
            v.push(random_u8);
        }
        let mut kec = sha3::v224();
        kec.absorb(&v);
        kec.unabsorb(&v[500..]);
        let mut kec2 = sha3::v224();
        kec2.absorb(&v[..500]);
        assert_eq!(kec.squeeze(), kec2.squeeze());

        // Sha3 256
        let mut v = vec![];
        for _ in 0..1000 {
            let random_u8: u8 = rng.gen();
            v.push(random_u8);
        }
        let mut kec = sha3::v256();
        kec.absorb(&v);
        kec.unabsorb(&v[500..]);
        let mut kec2 = sha3::v256();
        kec2.absorb(&v[..500]);
        assert_eq!(kec.squeeze(), kec2.squeeze());

        // Sha3 384
        let mut v = vec![];
        for _ in 0..1000 {
            let random_u8: u8 = rng.gen();
            v.push(random_u8);
        }
        let mut kec = sha3::v384();
        kec.absorb(&v);
        kec.unabsorb(&v[500..]);
        let mut kec2 = sha3::v384();
        kec2.absorb(&v[..500]);
        assert_eq!(kec.squeeze(), kec2.squeeze());

        // Sha3 512
        let mut v = vec![];
        for _ in 0..1000 {
            let random_u8: u8 = rng.gen();
            v.push(random_u8);
        }
        let mut kec = sha3::v512();
        kec.absorb(&v);
        kec.unabsorb(&v[500..]);
        let mut kec2 = sha3::v512();
        kec2.absorb(&v[..500]);
        assert_eq!(kec.squeeze(), kec2.squeeze());

    }
}
