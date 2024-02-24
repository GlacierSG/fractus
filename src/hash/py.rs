use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::wrap_pyfunction;


macro_rules! make_py_func {
    ($($name:ident),*) => {
        $(
            fn $name(py: Python) -> PyResult<&PyModule> {
                let $name = PyModule::new(py, stringify!($name))?;

                #[pyfunction]
                fn compute(py: Python, data: &[u8]) -> PyResult<Py<PyBytes>> {
                    let out = crate::hash::$name::compute(data);
                    Ok(PyBytes::new(py, &out).into())
                }

                #[pyfunction]
                fn extend(py: Python, original_hash: &[u8], original_size: usize, extended_data: &[u8]) -> PyResult<Py<PyBytes>> {
                    let out = crate::hash::$name::extend(original_hash.try_into().expect("Wrong original_hash size"), 
                        original_size, 
                        extended_data);
                    Ok(PyBytes::new(py, &out).into())
                }

                #[pyfunction]
                fn padding(py: Python, data_len: usize) -> PyResult<Py<PyBytes>> {
                    let out = crate::hash::$name::padding(data_len);
                    Ok(PyBytes::new(py, &out).into())
                }

                $name.add_function(wrap_pyfunction!(compute, $name)?)?;
                $name.add_function(wrap_pyfunction!(extend, $name)?)?;
                $name.add_function(wrap_pyfunction!(padding, $name)?)?;
                Ok($name)
            }
        )*

        pub fn hash(py: Python, m: &PyModule)  -> PyResult<()> {
            $(
                m.add_submodule($name(py)?)?;
            )*
            Ok(())
        }
    };
}

make_py_func!(
    md4, md5, ripemd128, ripemd160, ripemd256, ripemd320, sha0, sha1, sha2_256, sha2_512, whirlpool
);

