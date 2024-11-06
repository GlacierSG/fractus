use pyo3::prelude::*;
use crate::hash::py::{hash, keccak_hash};
use crate::cipher::py::cipher;
use std::process;
use crate::Error;
use pyo3::exceptions::PyRuntimeError;

impl From<Error> for PyErr {
    fn from(err: Error) -> PyErr {
        PyRuntimeError::new_err(format!("Error: {}", err))
    }
}

#[pymodule]
#[pyo3(name = "fractus")]
fn fractus(m: &Bound<'_, PyModule>) -> PyResult<()> {
    ctrlc::set_handler(move || {
        process::exit(130); 
    }).expect("Error setting Ctrl+C handler");

    let _ = hash(&m);
    let _ = cipher(&m);
    let _ = keccak_hash(&m);
    Ok(())
}
