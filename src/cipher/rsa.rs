use amalie::{zz, ZZ, totient, continued_fraction, gcd, egcd, mod_inv};
use crate::{Error, Result};
use ::pem::parse;
use x509_parser::prelude::*;
use rsa::{RsaPublicKey, RsaPrivateKey, pkcs1::{DecodeRsaPublicKey, DecodeRsaPrivateKey}};
use rsa::traits::{PublicKeyParts, PrivateKeyParts};
use std::fmt;


/// Factor using n and phi when n is factored into 2 primes
pub fn factor_with_phi_2(n: &ZZ, phi: &ZZ) -> (ZZ, ZZ) {
    let t: ZZ = (n + 1u8 - phi).pow(zz!(2)) - 4*n;
    let p = (t.clone() - 1) / 2;
    let q = (t + 1) / 2;
    (p, q)
}

pub fn factor_with_phi(n: &ZZ, phi: &ZZ) -> Vec<ZZ> {
    todo!();
}

pub fn factor_with_d(n: impl AsRef<ZZ>, e: impl AsRef<ZZ>, d: impl AsRef<ZZ>) -> ZZ {
    let n = n.as_ref();
    let e = e.as_ref();
    let d = d.as_ref();

    let k = e*d-1;
    let mut t = 0;
    while (&k >> t) & 1 == 0 {
        t += 1;
    }
    loop {
        let g = ZZ::rand_range(zz!(2), n);
        for i in 1..=t {
            let x = g.mod_pow(&k>>i, n);
            let p = gcd(n, x-1);
            if 1 < &p && &p < n && n % &p == 0 {
                return p;
            }
        }
    }
}

pub fn wiener_attack(n: impl AsRef<ZZ>, e: impl AsRef<ZZ>) -> Result<ZZ> {
    let n = n.as_ref();
    let e = e.as_ref();

    for (num, den) in continued_fraction(e.clone(), n.clone()) {
        if zz!(2).mod_pow(e, n).mod_pow(&den, n) != 2 {
            continue
        }
        return Ok((e * den - 1) / num);
    }
    return Err(Error::NoResult);
}


pub fn fermat_attack(n: impl AsRef<ZZ>) -> (ZZ, ZZ) {
    let n = n.as_ref();

    if n.is_even() {
        return (zz!(2), n/2);
    }

    let mut a = n.root_ceil(zz!(2));
    while !(a.pow(zz!(2)) - n).is_square() {
        a += 1;
    }
    let b = (a.pow(zz!(2)) - n).root_floor(zz!(2));
    return (&a - &b, &a + &b);
}

#[derive(Clone)]
pub struct Rsa {
    pub pt: Option<ZZ>,
    pub ct: Option<ZZ>,
    pub n: Option<ZZ>,
    pub e: Option<ZZ>,
    pub d: Option<ZZ>,
    //pub pre_d: Option<Vec<ZZ>>, // pre computed d
    //pub qinv: Option<ZZ>,
    pub phi: Option<ZZ>,
    pub factors: Vec<ZZ>,
    pub autofill: bool
}

impl Rsa {
    pub fn to_string(&self) -> String {
        let mut out = String::new();
        out.push_str("Rsa(");
        if let Some(v) = &self.pt {
            out.push_str("pt=");
            out.push_str(&v.to_string());
            out.push_str(", ");
        }
        if let Some(v) = &self.ct {
            out.push_str("ct=");
            out.push_str(&v.to_string());
            out.push_str(", ");
        }
        if let Some(v) = &self.n {
            out.push_str("n=");
            out.push_str(&v.to_string());
            out.push_str(", ");
        }
        if let Some(v) = &self.e {
            out.push_str("e=");
            out.push_str(&v.to_string());
            out.push_str(", ");
        }
        if let Some(v) = &self.d {
            out.push_str("d=");
            out.push_str(&v.to_string());
            out.push_str(", ");
        }
        if let Some(v) = &self.phi {
            out.push_str("phi=");
            out.push_str(&v.to_string());
            out.push_str(", ");
        }
        if self.factors.len() != 0 {
            out.push_str("factors=[");
            for x in &self.factors {
                out.push_str(&x.to_string());
                out.push_str(", ");
            }
            out.remove(out.len()-1);
            out.remove(out.len()-1);
            out.push_str("], ");
        }
        if out.len() > 4 {
            out.remove(out.len()-1);
            out.remove(out.len()-1);
        }
        out.push_str(")");
        out
    }
}


impl Rsa {
    pub fn new() -> Rsa {
        Rsa {
            pt: None,
            ct: None,
            n: None,
            e: None,
            d: None,
            phi: None,
            factors: vec![],
            autofill: true,
        }
    }

    pub fn guess(&mut self) {
        self.fill();
        match (&self.pt, &self.ct, &self.e, &self.n) {
            (Some(pt), Some(ct), Some(e), Some(n)) => {
                let v = (ct.pow(e) - pt).gcd(n);
                if v != 1 {
                    if v.is_prime() {
                        self.factors.push(v);
                    }
                    else {
                        // TODO: log that partial factor was found
                    }
                }
            }
            _ => {}
        }
    }

    pub fn fill(&mut self) {
        loop {
            match (&self.pt, &self.ct, &self.n, &self.e, &self.d, &self.phi, self.factors.len() != 0) {
                (_, _, None, _, _, _, true) => {
                    self.n = Some(self.factors.iter().product());
                },
                (_, _, _, _, _, None, true) => {
                    self.phi = Some(totient(&self.factors));
                },
                (_, _, _, Some(e), None, Some(phi), _) => {
                    self.d = Some(e.mod_pow(zz!(-1), phi));
                },
                (_, _, _, None, Some(d), Some(phi), _) => {
                    self.e = Some(d.mod_pow(zz!(-1), phi));
                },
                (None, Some(ct), Some(n), Some(e), _, _, _) => {
                    self.pt = Some(ct.mod_pow(e, n))
                },
                (Some(pt), None, Some(n), _, Some(d), _, _) => {
                    self.ct = Some(pt.mod_pow(d, n))
                },
                _ => {
                    return;
                }
            }
        }
    }

    pub fn from_pem(&mut self, pem: impl AsRef<str>) -> Result<()> {
        let pem_data = pem.as_ref();
        let pem = parse(pem_data).expect("Failed to parse PEM");

        if pem.tag() == "RSA PRIVATE KEY" {
            let dec = RsaPrivateKey::from_pkcs1_pem(pem_data).expect("Could not parse pem");
            self.n = Some(ZZ::from_bytes_be(&dec.n().to_bytes_be()));
            self.e = Some(ZZ::from_bytes_be(&dec.e().to_bytes_be()));
            self.d = Some(ZZ::from_bytes_be(&dec.d().to_bytes_be()));
            let primes = dec.primes();
            let mut factors = vec![];
            for p in primes {
                factors.push(ZZ::from_bytes_be(&p.to_bytes_be()));
            }
            self.factors = factors;

            if self.autofill { self.fill(); }
        }
        else if pem.tag() == "RSA PUBLIC KEY" {
            let dec = RsaPublicKey::from_pkcs1_pem(pem_data).expect("Could not parse pem");
            self.n = Some(ZZ::from_bytes_be(&dec.n().to_bytes_be()));
            self.e = Some(ZZ::from_bytes_be(&dec.e().to_bytes_be()));

            if self.autofill { self.fill(); }
        }
        else if pem.tag() == "CERTIFICATE" {
            let (_rem, cert) = X509Certificate::from_der(pem.contents()).expect("Failed to parse certificate");
            let public_key = cert.public_key();
            let rsa_pub_key = RsaPublicKey::from_pkcs1_der(&public_key.subject_public_key.data).expect("Failed to parse RSA public key");

            self.n = Some(ZZ::from_bytes_be(&rsa_pub_key.n().to_bytes_be()));
            self.e = Some(ZZ::from_bytes_be(&rsa_pub_key.e().to_bytes_be()));

            if self.autofill { self.fill(); }
        }
        else {
            return Err(Error::CouldNotParse);
        }

        Ok(())
    }
    pub fn enc(&mut self, ct: impl AsRef<ZZ>) -> Result<ZZ> {
        if self.autofill { self.fill(); }

        let ct = ct.as_ref();

        match (&self.n, &self.e) {
            (Some(n), Some(e)) => {
                Ok(ct.mod_pow(e, n))
            },
            _ => {
                return Err(Error::InvalidState("missing self.e".to_string()));
            },
        }
    }
    pub fn dec(&mut self, msg: impl AsRef<ZZ>) -> Result<ZZ> {
        if self.autofill { self.fill(); }

        let msg = msg.as_ref();

        match (&self.n, &self.d) {
            (Some(n), Some(d)) => {
                Ok(msg.mod_pow(d, n))
            },
            _ => {
                return Err(Error::InvalidState("missing self.n or/and self.d".to_string()));
            },
        }
    }
    pub fn wiener(&mut self) -> Result<()> {
        if self.autofill { self.fill(); }

        match (&self.n, &self.e) {
            (Some(n), Some(e)) => {
                let phi = wiener_attack(n, e)?;
                self.phi = Some(phi);
                if self.autofill { self.fill(); }
                return Ok(());
            },
            _ => {
                return Err(Error::InvalidState("missing self.n or/and self.e".to_string()));
            }
        }
    }
    pub fn fermat(&mut self) -> Result<()> {
        if self.autofill { self.fill(); }

        match &self.n {
            Some(n) => {
                let factors = fermat_attack(n);
                self.factors = vec![factors.0, factors.1];
                if self.autofill { self.fill(); }
                return Ok(());
            },
            _ => {
                return Err(Error::InvalidState("missing self.n or/and self.e".to_string()));
            }
        }
    }
    pub fn factorize(&mut self) {
        if self.autofill { self.fill(); }

        if let Some(n) = &self.n {
            if n.is_prime() {
                self.factors = vec![n.clone()];

                if self.autofill { self.fill(); }
                return;
            }
        }

        if let (Some(n), Some(phi)) = (&self.n, &self.phi) {
            let (p, q) = factor_with_phi_2(n, phi);
            if &(&p*&q) == n {
                self.factors = vec![p, q];

                if self.autofill { self.fill(); }
                return;
            }
            else {
                // TODO
            }
        }
        if let (Some(n), Some(e), Some(d)) = (&self.n, &self.e, &self.d) {
            let p = factor_with_d(n, e, d);
            let q = n/&p;
            self.factors = vec![p, q];
            if self.autofill { self.fill(); }
            return;
        }
    }

    pub fn same_pt(&mut self, rsa: &Rsa) {
        if self.autofill { self.fill(); }

        match (&self.ct, &self.e, &self.n) {
            (Some(c1), Some(e1), Some(n1)) => {
                match (&rsa.ct, &rsa.e, &rsa.n) {
                    (Some(c2), Some(e2), Some(n2)) => {
                        assert_eq!(n1, n2, "self.n != rsa.n");
                        let (g, y, x) = egcd(e1, e2);
                        let p1 = if x > 0 { c1.mod_pow(x, n1) }
                                 else { mod_inv(c1, n1).expect("gcd(self.c, rsa.n) != 1").mod_pow(-x, n1) };
                        let p2 = if y > 0 { c2.mod_pow(y, n2) }
                                 else { mod_inv(c2, n2).expect("gcd(self.c, rsa.n) != 1").mod_pow(-y, n2) };
                        if g != 1 {
                            self.pt = Some(((p1*p2) % n2).nth_root(g).expect("Could not calculate nth_root of plaintexts"));
                        }
                        else {
                            self.pt = Some((p1*p2) % n2);
                        }
                        if self.autofill { self.fill(); }
                    },
                    _ => {}
                }
            },
            _ => {}
        }
    }

    pub fn recover_n(&mut self, others: &Vec<Rsa>) -> Result<()> {
        if let (Some(e), Some(pt), Some(ct)) = (&self.e, &self.pt, &self.ct) {
            let mut n = ct - pt.pow(e);
            for rsa in others {
                if let (Some(pt2), Some(ct2)) = (&rsa.pt, &rsa.ct) {
                    n = gcd(n, ct2 - pt2.pow(e));
                }
            }
            if n == 1 {
                return Err(Error::NoResult);
            }
            self.n = Some(n);
        }
        else {
            return Err(Error::InvalidState("missing self.e, self.pt or self.ct".to_string()));
        }
        Ok(())
    }
}
