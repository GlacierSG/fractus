use pyo3::prelude::*;
use super::hash::py::hash;
use std::process;

#[pymodule]
#[pyo3(name = "fractus")]
fn fractus(py: Python, m: &PyModule) -> PyResult<()> {
    ctrlc::set_handler(move || {
        process::exit(130); 
    }).expect("Error setting Ctrl+C handler");

    let _ = hash(py, &m);
    Ok(())
}
