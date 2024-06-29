use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyString, PyAny};
use pyo3::wrap_pyfunction;

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

