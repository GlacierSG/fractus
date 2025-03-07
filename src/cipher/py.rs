use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyString, PyAny, PyLong, PyFunction};
use num_bigint::BigInt;
use amalie::ZZ;

pub fn cipher(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Replacer>()?;
    m.add_class::<Rsa>()?;
    Ok(())
}


#[pyclass]
pub struct Replacer {
    sub: crate::Replacer
}

#[pymethods]
impl Replacer {
    #[new]
    #[pyo3(signature = (tokens=None))]
    fn new(tokens: Option<String>) -> Replacer {
        let mut sub = crate::Replacer::new();

        if let Some(tokens) = tokens {
            sub.tokens(tokens);
        }
        Replacer{ sub }
    }
    fn replace(&mut self, lhs: String, rhs: String) {
        self.sub.replace(lhs, rhs);
    }
    fn replace_chars(&mut self, lhs: String, rhs: String) {
        for (l,r) in lhs.chars().zip(rhs.chars()) {
            self.sub.replace(l.to_string(), r.to_string());
        }
    }

    fn caesar(&mut self, alphabet: String, key: i32) {
        self.sub.caesar(alphabet, key);
    }
    fn result(&self) -> String {
        self.sub.result()
    }
    fn count(&self) -> Vec<(String, usize)> {
        self.sub.count()
    }
    
    fn __str__(&self) -> PyResult<String> {
        Ok(format!("{}", self.sub))
    }
}


#[pyclass]
#[derive(Clone)]
pub struct Rsa {
    rsa: crate::Rsa
}


#[pymethods]
impl Rsa {
    #[new]
    #[pyo3(signature = (pt=None, ct=None, n=None, e=None, d=None, phi=None, factors=None))]
    fn new(pt: Option<BigInt>, ct: Option<BigInt>, n: Option<BigInt>, e: Option<BigInt>, d: Option<BigInt>, phi: Option<BigInt>, factors: Option<Vec<BigInt>>) -> Rsa {
        let mut rsa = crate::Rsa::new();
        if let Some(pt) = pt {
            let pt: ZZ = pt.into();
            rsa.pt = Some(pt);
        }
        if let Some(ct) = ct {
            let ct: ZZ = ct.into();
            rsa.ct = Some(ct);
        }
        if let Some(n) = n {
            let n: ZZ = n.into();
            rsa.n = Some(n);
        }
        if let Some(e) = e {
            let e: ZZ = e.into();
            rsa.e = Some(e);
        }
        if let Some(d) = d {
            let d: ZZ = d.into();
            rsa.d = Some(d);
        }
        if let Some(phi) = phi {
            let phi: ZZ = phi.into();
            rsa.phi = Some(phi);
        }
        if let Some(factors) = factors {
            rsa.factors = factors.iter().map(|x| { let x: ZZ = x.clone().into(); x }).collect();
        }
        Rsa{ rsa: rsa }
    }

    #[getter]
    fn get_pt(&self) -> Option<BigInt> {
        if let Some(x) = &self.rsa.pt {
            let x: BigInt = x.clone().into();
            Some(x)
        }
        else {
            None
        }
    }
    #[setter]
    fn set_pt(&mut self, value: Option<BigInt>) {
        if let Some(v) = value {
            let v: ZZ = v.into();
            self.rsa.pt = Some(v);
        }
        else {
            self.rsa.pt = None;
        }
    }

    #[getter]
    fn get_ct(&self) -> Option<BigInt> {
        if let Some(x) = &self.rsa.ct {
            let x: BigInt = x.clone().into();
            Some(x)
        }
        else {
            None
        }
    }
    #[setter]
    fn set_ct(&mut self, value: Option<BigInt>) {
        if let Some(v) = value {
            let v: ZZ = v.into();
            self.rsa.ct = Some(v);
        }
        else {
            self.rsa.ct = None;
        }
    }

    #[getter]
    fn get_n(&self) -> Option<BigInt> {
        if let Some(x) = &self.rsa.n {
            let x: BigInt = x.clone().into();
            Some(x)
        }
        else {
            None
        }
    }
    #[setter]
    fn set_n(&mut self, value: Option<BigInt>) {
        if let Some(v) = value {
            let v: ZZ = v.into();
            self.rsa.n = Some(v);
        }
        else {
            self.rsa.n = None;
        }
    }

    #[getter]
    fn get_e(&self) -> Option<BigInt> {
        if let Some(x) = &self.rsa.e {
            let x: BigInt = x.clone().into();
            Some(x)
        }
        else {
            None
        }
    }
    #[setter]
    fn set_e(&mut self, value: Option<BigInt>) {
        if let Some(v) = value {
            let v: ZZ = v.into();
            self.rsa.e = Some(v);
        }
        else {
            self.rsa.e = None;
        }
    }

    #[getter]
    fn get_d(&self) -> Option<BigInt> {
        if let Some(x) = &self.rsa.d {
            let x: BigInt = x.clone().into();
            Some(x)
        }
        else {
            None
        }
    }
    #[setter]
    fn set_d(&mut self, value: Option<BigInt>) {
        if let Some(v) = value {
            let v: ZZ = v.into();
            self.rsa.d = Some(v);
        }
        else {
            self.rsa.d = None;
        }
    }

    #[getter]
    fn get_phi(&self) -> Option<BigInt> {
        if let Some(x) = &self.rsa.phi {
            let x: BigInt = x.clone().into();
            Some(x)
        }
        else {
            None
        }
    }
    #[setter]
    fn set_phi(&mut self, value: Option<BigInt>) {
        if let Some(v) = value {
            let v: ZZ = v.into();
            self.rsa.phi = Some(v);
        }
        else {
            self.rsa.phi = None;
        }
    }

    #[getter]
    fn get_factors(&self) -> Vec<BigInt> {
        self.rsa.factors.iter().map(|x| { let x: BigInt = x.clone().into(); x }).collect()
    }
    #[setter]
    fn set_factors(&mut self, value: Vec<BigInt>) {
        self.rsa.factors = value.iter().map(|x| { let x: ZZ = x.clone().into(); x }).collect();
    }
    fn __str__(&self) -> String {
        self.rsa.to_string()
    }
    
    fn guess(&mut self) {
        self.rsa.guess();
    }

    fn from_pem(&mut self, inp: String) -> PyResult<()> {
        self.rsa.from_pem(&inp)?;
        Ok(())
    }
    fn enc(&mut self, inp: BigInt) -> PyResult<BigInt> {
        let inp: ZZ = inp.into();
        let out = self.rsa.enc(&inp)?;
        Ok(out.into())
    }
    fn dec(&mut self, inp: BigInt) -> PyResult<BigInt> {
        let inp: ZZ = inp.into();
        let out = self.rsa.dec(&inp)?;
        Ok(out.into())
    }
    fn wiener(&mut self) -> PyResult<()> {
        self.rsa.wiener()?;
        Ok(())
    }
    fn fermat(&mut self) -> PyResult<()> {
        self.rsa.fermat()?;
        Ok(())
    }
    fn fill(&mut self) -> PyResult<()> {
        self.rsa.fill();
        Ok(())
    }
    fn factorize(&mut self) -> PyResult<()> {
        self.rsa.factorize();
        Ok(())
    }
    fn same_pt(&mut self, rsa: &Rsa) -> PyResult<()> {
        self.rsa.same_pt(&rsa.rsa);
        Ok(())
    }
    fn recover_n(&mut self, rsa: Vec<Bound<'_, PyAny>>) -> PyResult<()> {
        let mut v = vec![];
        for r in rsa {
            let r: Rsa = r.extract()?;
            v.push(r.rsa);
        }
        self.rsa.recover_n(&v)?;
        Ok(())
    }
}
