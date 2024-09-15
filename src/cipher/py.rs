use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyString, PyAny, PyLong, PyFunction};
use num_bigint::BigInt;
use pyo3::wrap_pyfunction;
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
    #[pyo3(signature = (tokens=None, alphabet=None))]
    fn new(tokens: Option<String>, alphabet: Option<String>) -> Replacer {
        let mut sub = crate::Replacer::new();

        if let Some(alphabet) = alphabet {
            sub.alphabet(alphabet);
        }
        if let Some(tokens) = tokens {
            sub.tokens(tokens);
        }
        Replacer{ sub }
    }
    fn replace(&mut self, lhs: String, rhs: String) {
        self.sub.replace(lhs, rhs);
    }

    fn ceasar(&mut self, key: i32) {
        self.sub.ceasar(key);
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
pub struct Rsa {
    rsa: crate::Rsa
}

#[pymethods]
impl Rsa {
    #[new]
    #[pyo3(signature = (n=None, e=None, d=None, phi=None, factors=None))]
    fn new(n: Option<BigInt>, e: Option<BigInt>, d: Option<BigInt>, phi: Option<BigInt>, factors: Option<Vec<BigInt>>) -> Rsa {
        let mut rsa = crate::Rsa::new();
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
            rsa.factors = Some(factors.iter().map(|x| { let x: ZZ = x.clone().into(); x }).collect());
        }
        Rsa{ rsa: rsa }
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
    fn get_factors(&self) -> Option<Vec<BigInt>> {
        if let Some(factors) = &self.rsa.factors {
            Some(factors.iter().map(|x| { let x: BigInt = x.clone().into(); x }).collect())
        }
        else {
            None
        }
    }
    #[setter]
    fn set_factors(&mut self, value: Option<Vec<BigInt>>) {
        if let Some(value) = value {
            self.rsa.factors = Some(value.iter().map(|x| { let x: ZZ = x.clone().into(); x }).collect());
        }
        else {
            self.rsa.factors = None;
        }
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
        let out = self.rsa.enc(&inp)?;
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
}
