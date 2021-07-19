use std::{borrow::Cow, error::Error, ffi::OsStr, fs::File, io::BufReader, path::Path};

use log::{debug, error};
use serde::Deserialize;

pub trait Loadable: for<'de> Deserialize<'de> {
    fn read_from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn Error>> {
        // Open the file in read-only mode with buffer.
        let file = File::open(path)?;
        let reader = BufReader::new(file);

        // Read the JSON contents of the file as an instance of `User`.
        let u = serde_json::from_reader(reader)?;

        // Return the `User`.
        Ok(u)
    }

    fn load<P: AsRef<Path>>(path: P) -> Option<Self> {
        let path: &Path = path.as_ref();
        match Self::read_from_file(path) {
            Ok(data) => {
                debug!(
                    "Found '{}' valueset",
                    path.file_name()
                        .map(OsStr::to_string_lossy)
                        .unwrap_or(Cow::Borrowed("???"))
                );
                Some(data)
            }
            Err(e) => {
                error!("{}", e);
                None
            }
        }
    }
}
