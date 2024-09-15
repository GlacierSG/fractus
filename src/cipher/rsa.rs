use amalie::{zz, ZZ, alg::totient, alg::continued_fraction, alg::gcd};
use crate::{Error, Result};
use ::pem::parse;
use x509_parser::prelude::*;
use rsa::{RsaPublicKey, RsaPrivateKey, pkcs1::{DecodeRsaPublicKey, DecodeRsaPrivateKey}};
use rsa::traits::{PublicKeyParts, PrivateKeyParts};

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


pub struct Rsa {
    pub n: Option<ZZ>,
    pub e: Option<ZZ>,
    pub d: Option<ZZ>,
    //pub pre_d: Option<Vec<ZZ>>, // pre computed d
    //pub qinv: Option<ZZ>,
    pub phi: Option<ZZ>,
    pub factors: Option<Vec<ZZ>>,
}

impl Rsa {
    pub fn new() -> Rsa {
        Rsa {
            n: None,
            e: None,
            d: None,
            phi: None,
            factors: None,
        }
    }

    pub fn fill(&mut self) {
        loop {
            match (&self.n, &self.e, &self.d, &self.phi, &self.factors) {
                (None, _, _, _, Some(factors)) => {
                    self.n = Some(factors.iter().product());
                },
                (_, _, _, None, Some(factors)) => {
                    self.phi = Some(totient(factors));
                },
                (_, Some(e), None, Some(phi), _) => {
                    self.d = Some(e.mod_pow(zz!(-1), phi));
                },
                (_, None, Some(d), Some(phi), _) => {
                    self.e = Some(d.mod_pow(zz!(-1), phi));
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
            self.factors = Some(factors);
        }
        else if pem.tag() == "RSA PUBLIC KEY" {
            let dec = RsaPublicKey::from_pkcs1_pem(pem_data).expect("Could not parse pem");
            self.n = Some(ZZ::from_bytes_be(&dec.n().to_bytes_be()));
            self.e = Some(ZZ::from_bytes_be(&dec.e().to_bytes_be()));
        }
        else if pem.tag() == "CERTIFICATE" {
            let (_rem, cert) = X509Certificate::from_der(pem.contents()).expect("Failed to parse certificate");
            let public_key = cert.public_key();
            let rsa_pub_key = RsaPublicKey::from_pkcs1_der(&public_key.subject_public_key.data).expect("Failed to parse RSA public key");

            self.n = Some(ZZ::from_bytes_be(&rsa_pub_key.n().to_bytes_be()));
            self.e = Some(ZZ::from_bytes_be(&rsa_pub_key.e().to_bytes_be()));
        }
        else {
            return Err(Error::CouldNotParse);
        }

        Ok(())
    }
    pub fn enc(&mut self, ct: impl AsRef<ZZ>) -> Result<ZZ> {
        let ct = ct.as_ref();

        self.fill();

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
        let msg = msg.as_ref();

        self.fill();

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
        match (&self.n, &self.e) {
            (Some(n), Some(e)) => {
                let phi = wiener_attack(n, e)?;
                self.phi = Some(phi);
                return Ok(());
            },
            _ => {
                return Err(Error::InvalidState("missing self.n or/and self.e".to_string()));
            }
        }
    }
    pub fn fermat(&mut self) -> Result<()> {
        match &self.n {
            Some(n) => {
                let factors = fermat_attack(n);
                self.factors = Some(vec![factors.0, factors.1]);
                return Ok(());
            },
            _ => {
                return Err(Error::InvalidState("missing self.n or/and self.e".to_string()));
            }
        }
    }
    pub fn factorize(&mut self) {
        if self.factors != None { 
            return;
        }
        if let Some(n) = &self.n {
            if n.is_prime() {
                self.factors = Some(vec![n.clone()]);
                return;
            }
        }

        if let (Some(n), Some(phi)) = (&self.n, &self.phi) {
            let (p, q) = factor_with_phi_2(n, phi);
            if &(&p*&q) == n {
                self.factors = Some(vec![p, q]);
                return;
            }
            else {
                // TODO
            }
        }
        if let (Some(n), Some(e), Some(d)) = (&self.n, &self.e, &self.d) {
            let p = factor_with_d(n, e, d);
            let q = n/&p;
            self.factors = Some(vec![p, q]);
            return;
        }
    }
}
