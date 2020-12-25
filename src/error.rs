use std::prelude::v1::*;

use std::{convert, fmt, result, str};

#[cfg(feature = "std")]
use std::error;

#[allow(unused)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum Error {
    /// Generic error type containing a string
    Other(&'static str),
    /// IO Error
    IO,
    /// Signature Error
    Signature(&'static str),
    /// Read Error
    Read(&'static str),
    /// memflow-core error.
    ///
    /// Catch-all for flow-core related errors.
    Core(::memflow::error::Error),
    /// memflow-win32 error.
    ///
    /// Catch-all for flow-win32 related errors.
    Win32(::memflow_win32::error::Error),
    /// PE error.
    ///
    /// Catch-all for pe related errors.
    PE(pelite::Error),
}

/// Convert from &str to error
impl convert::From<&'static str> for Error {
    fn from(error: &'static str) -> Self {
        Error::Other(error)
    }
}

/// Convert from io::Error
impl From<std::io::Error> for Error {
    fn from(_error: std::io::Error) -> Error {
        Error::IO
    }
}

/// Convert from memflow::Error
impl From<::memflow::error::Error> for Error {
    fn from(error: ::memflow::error::Error) -> Error {
        Error::Core(error)
    }
}

/// Convert from memflow::PartialError
impl<T> From<::memflow::error::PartialError<T>> for Error {
    fn from(error: ::memflow::error::PartialError<T>) -> Error {
        Error::Core(error.into())
    }
}

/// Convert from memflow_win32::Error
impl From<::memflow_win32::error::Error> for Error {
    fn from(error: ::memflow_win32::error::Error) -> Error {
        Error::Win32(error)
    }
}

/// Convert from pelite::Error
impl From<pelite::Error> for Error {
    fn from(error: pelite::Error) -> Error {
        Error::PE(error)
    }
}

#[allow(unused)]
impl Error {
    /// Returns a tuple representing the error description and its string value.
    pub fn to_str_pair(self) -> (&'static str, Option<&'static str>) {
        match self {
            Error::Other(e) => ("other error", Some(e)),
            Error::IO => ("io error", None),
            Error::Signature(e) => ("signature error", Some(e)),
            Error::Read(e) => ("read error", Some(e)),
            Error::Core(e) => ("error in core", Some(e.to_str())),
            Error::Win32(e) => ("error in win32", Some(e.to_str())),
            Error::PE(e) => ("error handling pe", Some(e.to_str())),
        }
    }

    /// Returns a simple string representation of the error.
    pub fn to_str(self) -> &'static str {
        self.to_str_pair().0
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let (desc, value) = self.to_str_pair();

        if let Some(value) = value {
            write!(f, "{}: {}", desc, value)
        } else {
            f.write_str(desc)
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for Error {
    fn description(&self) -> &str {
        self.to_str()
    }
}

/// Specialized `Result` type for flow-win32 errors.
pub type Result<T> = result::Result<T, Error>;
