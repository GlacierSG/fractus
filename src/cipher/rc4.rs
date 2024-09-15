use std::collections::BTreeMap;

fn ksa(key: &[u8]) -> Vec<u8> {
    let mut s: Vec<u8> = (0..=255).collect();
    let mut j:u8 = 0;
    for i in 0..=255 {
        j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
        s.swap(i, j.into());
    }
    s
}

pub fn process(m: impl AsRef<[u8]>, key: impl AsRef<[u8]>) -> Vec<u8> {
    let m = m.as_ref();
    let key = key.as_ref();

    let mut j = 0u8;

    let mut s = ksa(key);

    let mut out = Vec::with_capacity(m.len());
    for i in 0..m.len() {
        let t = (i+1) % 256;
        j = j.wrapping_add(s[t]);
        s.swap(t, j.into());
        let k = s[s[t].wrapping_add(s[j as usize]) as usize];
        out.push(k ^ m[i]);
    }
    out
}

/// Fluhrer-Mantin-Shamir attack
pub fn fms_attack<F>(oracle: F, key_len: u8) -> Result<Vec<u8>, ()>
where F: Fn(&[u8], &[u8]) -> Vec<u8>
{
    let mut key: Vec<u8> = vec![3, 255, 0];

    for k in 0u8..key_len {
        key[0] = k.wrapping_add(3);
        let mut counter = BTreeMap::new();
        for x in 0..=255 {
            key[2] = x;
            let c = oracle(b"\x00", &key[..3]);

            let mut s: Vec<u8> = (0..=255).collect();
            let mut j: u8 = 0;
            for i in 0..key.len() {
                j = j.wrapping_add(s[i]).wrapping_add(key[i]);
                s.swap(i, j.into());
            }
            let b = c[0].wrapping_sub(j).wrapping_sub(s[key.len()]);

            *counter.entry(b).or_insert(0) += 1;
        }
        match counter.into_iter()
            .max_by_key(|&(_, count)| count)
            .map(|(element, _)| element) {
            Some(v) => key.push(v),
            None => return Err(())
        }
    }
    Ok(key[3..].to_vec())
}

#[cfg(test)]
mod test {
    use super::{process, fms_attack};

    #[test]
    fn test_process() {
        assert_eq!(b"\xac\xff\xba".to_vec(), process(b"abc", b"abc"));
        assert_eq!(b"\x66\x1f\x53".to_vec(), process(b"msg", b"key"));
        assert_eq!(b"\x71\xdd\xf9\x7f\x23\xb8\xe4\x2a\x4f\x0c\xcc\x46\x3d\x7d\xa4\xaa\x3d\x0f\xe8\xb6\x30\xa3\x2d\x1d\x06\x54\xc5\x48\x1b\xd9\xdd\xd9\x93\x53\x8b\xf5\xa1\x30\x16\x75\xec\xdc\x4f\xcc\xe6\x33\x44\x1c\xb4\x18\x7e\xec\x5c\xb0\x60\xdc\x38\xb2\xab\xb6\x6c\xe6\x1f\x1a\x87\xef\x2e\x6b\x97\xd6\x8b\x0a\xef\x2d\x83\xa5\x48\x63\xc0\x7a\x8a\xfc\x0c\xbb\xc9\x83\x74\xe1\xe9\xc3\x62\xb9\x02\x7a\xc1\xd9\x87\x17\x04\x25\xf9\x0a\xfa\x0e\x11\x35\x8a\xd0\x09\x3c\x41\x4b\x32\xf3\xca\x05\x1d\xc0\xcf\xc3\x99\x0e\x1f\x5c\x22\x8c\x60\xb7\x06\x48\x78\x5a\x6e\xd9\x14\xd8\xcc\xdc\x4c\xae\x96\x32\x8a\xe1\x38\xb0\xf1\xdf\xc5\x8c\x5c\x44\xee\x83\xcb\xd9\xfa\x83\x7d\x03\x69\xf0\x91\x65\x8c\xe7\xdf\xea\x40\x85\x30\xb6\x07\x6f\x1d\xba\xc4\xfd\xde\xaa\x24\x98\xfc\x57\xe9\x9f\x1b\x94\xa7\x82\xad\x85\xb6\x37\xeb\x28\xe8\x0f\x49\x7c\xf5\x3f\x9d\x31\xe2\x0b\x8a\xcd\x21\xac\xeb\x67\xa9\x58\xa4\x10\x04\xc1\x9b\x29\xcf\x89\x8d\x89\xa2\x82\x0e\xa7\x6b\x2c\x97\x96\x98\x40\x93\x61\x0c\x8e\x4f\xfa\x21\xbe\x84\xdb\x7f\x93\x7e\xb5\xad\x66\x11\xc7\x85\xdf\xdd\x6c\x0e\x5a".to_vec(), process(b"a".repeat(258), b"a".repeat(256)));
    }

    #[test]
    fn fms() {
        for i in 0..7 {
            let secret = b"a".repeat(i);
            let f = |msg: &[u8], prefix: &[u8]| {
                let mut key = prefix.to_vec();
                key.extend(secret.clone());
                process(msg, key)
            };

            assert_eq!(secret.to_vec(), fms_attack(f, secret.len().try_into().unwrap()).unwrap());
        }
    }
}
