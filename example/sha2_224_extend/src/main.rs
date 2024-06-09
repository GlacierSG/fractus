use fractus::*;

fn main() {
    let m = b"abc";
    let h = sha2_224::compute(&m);
    let e = b"cde";
    let mut c = m.to_vec();
    c.extend(sha2_224::padding(m.len()));
    c.extend(e);

    let s256 = sha2_256::compute(&sha2_224::compute(&c));    

    let e = sha2_224::extend_par(&h, m.len(), e, |x| &sha2_256::compute(x) == &s256)[0];
    assert_eq!(e, sha2_224::compute(&c));
}
