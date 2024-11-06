use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyString, PyAny};
use pyo3::exceptions::PyTypeError;
use pyo3::wrap_pyfunction;
use super::{keccak, sha3};

fn pyany_to_bytes(data: &Bound<'_, PyAny>) -> PyResult<Vec<u8>> {
    if data.is_instance_of::<PyString>() {
        let data: String = data.extract()?;
        return Ok(data.into_bytes());
    }
    else {
        let data: Vec<u8> = data.extract()?;
        return Ok(data);
    }
}

macro_rules! make_py_func {
    ($($name:ident),*) => {
        $(
            fn $name(py: Python) -> PyResult<Bound<PyModule>> {
                let $name = PyModule::new_bound(py, stringify!($name))?;

                #[pyfunction]
                fn compute(py: Python, data: Bound<'_, PyAny>) -> PyResult<Py<PyBytes>> {
                    let data = pyany_to_bytes(&data)?;
                    let out = crate::hash::$name::compute(data);
                    return Ok(PyBytes::new_bound(py, &out).into())
                }

                #[pyfunction]
                fn extend(py: Python, original_hash: &[u8], original_size: usize, extend_data: Bound<'_, PyAny>) -> PyResult<Py<PyBytes>> {
                    let extend_data = pyany_to_bytes(&extend_data)?;
                    let out = crate::hash::$name::extend(original_hash.try_into().expect("Wrong original_hash size"), 
                        original_size, 
                        extend_data);
                    Ok(PyBytes::new_bound(py, &out).into())
                }

                #[pyfunction]
                fn padding(py: Python, data_len: usize) -> PyResult<Py<PyBytes>> {
                    let out = crate::hash::$name::padding(data_len);
                    Ok(PyBytes::new_bound(py, &out).into())
                }

                $name.add_function(wrap_pyfunction!(compute, &$name)?)?;
                $name.add_function(wrap_pyfunction!(extend, &$name)?)?;
                $name.add_function(wrap_pyfunction!(padding, &$name)?)?;
                Ok($name)
            }
        )*

        pub fn hash(m: &Bound<'_, PyModule>)  -> PyResult<()> {
            $(
                m.add_submodule(&$name(m.py())?)?;
            )*
            Ok(())
        }
    };
}

make_py_func!(
    md4, md5, ripemd128, ripemd160, ripemd256, ripemd320, sha0, sha1, sha2_224, sha2_256, sha2_512, whirlpool
);



macro_rules! impl_keccak {
    ($struct_name:ident, $substruct:ident) => {
        #[pyclass]
        struct $struct_name {
            pub(crate) v: keccak::Keccak,
        }

        #[pymethods]
        impl $struct_name {
            #[new]
            fn new(bitrate: usize, width: usize) -> Self {
                Self { v: $substruct::new(bitrate, width) }
            }

            #[pyo3(signature = (data))]
            fn absorb(&mut self, data: Bound<'_, PyAny>) -> PyResult<()> {
                let data = pyany_to_bytes(&data)?;
                self.v.absorb(data);
                Ok(())
            }
            #[pyo3(signature = (data))]
            fn unabsorb(&mut self, data: Bound<'_, PyAny>) -> PyResult<()> {
                let data = pyany_to_bytes(&data)?;
                self.v.unabsorb(data);
                Ok(())
            }
            fn squeeze(&mut self, py: Python) -> PyResult<Py<PyBytes>> {
                Ok(PyBytes::new_bound(py, &self.v.squeeze()).into())
            }

            fn f(&mut self) {
                self.v.f();
            }
            fn f_inv(&mut self) {
                self.v.f_inv();
            }

            #[getter]
            fn get_state(&self) -> [u64; 25] {
                self.v.state
            }
            #[setter]
            fn set_state(&mut self, value: [u64; 25]) -> () {
                self.v.state = value;
            }

            #[getter]
            fn get_bitrate(&self) -> usize {
                self.v.bitrate
            }
            #[setter]
            fn set_bitrate(&mut self, value: usize) -> () {
                self.v.bitrate = value;
            }

            #[getter]
            fn get_size(&self) -> usize {
                self.v.size
            }
            #[setter]
            fn set_size(&mut self, value: usize) -> () {
                self.v.size = value;
            }

            #[getter]
            fn get_width(&self) -> usize {
                self.v.width
            }
            #[setter]
            fn set_width(&mut self, value: usize) -> () {
                self.v.width = value;
            }
            #[getter]
            fn get_d(&self) -> u8 {
                self.v.d
            }
            #[setter]
            fn set_d(&mut self, value: u8) -> () {
                self.v.d = value;
            }
        }
    }
}
impl_keccak!(Keccak, keccak);
impl_keccak!(Sha3, sha3);

pub fn keccak_hash(m: &Bound<'_, PyModule>) -> PyResult<()> {
    {
        #[pyfunction]
        fn v224() -> Keccak {
            Keccak{ v: keccak::v224() }
        }
        #[pyfunction]
        fn v256() -> Keccak {
            Keccak{ v: keccak::v256() }
        }
        #[pyfunction]
        fn v384() -> Keccak {
            Keccak{ v: keccak::v384() }
        }
        #[pyfunction]
        fn v512() -> Keccak {
            Keccak{ v: keccak::v512() }
        }
        let keccak = PyModule::new_bound(m.py(), "keccak")?;
        keccak.add_class::<Keccak>()?;
        keccak.add_function(wrap_pyfunction!(v224, m)?)?;
        keccak.add_function(wrap_pyfunction!(v256, m)?)?;
        keccak.add_function(wrap_pyfunction!(v384, m)?)?;
        keccak.add_function(wrap_pyfunction!(v512, m)?)?;
        let _ = m.add_submodule(&keccak);
    };
    {
        #[pyfunction]
        fn v224() -> Sha3 {
            Sha3 { v: sha3::v224() }
        }
        #[pyfunction]
        fn v256() -> Sha3 {
            Sha3 { v: sha3::v256() }
        }
        #[pyfunction]
        fn v384() -> Sha3 {
            Sha3 { v: sha3::v384() }
        }
        #[pyfunction]
        fn v512() -> Sha3 {
            Sha3 { v: sha3::v512() }
        }
        let sha3 = PyModule::new_bound(m.py(), "sha3")?;
        sha3.add_class::<Sha3>()?;
        sha3.add_function(wrap_pyfunction!(v224, m)?)?;
        sha3.add_function(wrap_pyfunction!(v256, m)?)?;
        sha3.add_function(wrap_pyfunction!(v384, m)?)?;
        sha3.add_function(wrap_pyfunction!(v512, m)?)?;
        let _ = m.add_submodule(&sha3);
    };
    Ok(())
}


