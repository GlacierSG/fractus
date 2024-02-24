use pyo3::prelude::*;
use super::hash::py::hash;

#[pymodule]
#[pyo3(name = "fractus")]
fn fractus(py: Python, m: &PyModule) -> PyResult<()> {
    let _ = hash(py, &m);
    Ok(())
}
