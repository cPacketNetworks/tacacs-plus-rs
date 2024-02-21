mod protocol;
mod session;

#[macro_use]
extern crate bitflags;

#[cfg(feature = "std")]
use thiserror::Error;

#[cfg(feature = "std")]
#[derive(Error, Debug)]
pub enum TacacsError {
    #[error("Connection to TACACS+ server failed")]
    ConnectionError,

    #[error("The TACACS+ server sent an invalid or corrupt response")]
    BadResponse,

    #[error(transparent)]
    IOError(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
