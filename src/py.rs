use pyo3::prelude::*;
use crate::hash::py::hash;
use std::process;

#[pymodule]
#[pyo3(name = "fractus")]
fn fractus(m: &Bound<'_, PyModule>) -> PyResult<()> {
    ctrlc::set_handler(move || {
        process::exit(130); 
    }).expect("Error setting Ctrl+C handler");

    let _ = hash(&m);
    Ok(())
}
