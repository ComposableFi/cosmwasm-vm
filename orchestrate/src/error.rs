use core::fmt::Display;

#[derive(Debug)]
pub enum Error {
    Network,
    CannotDecode,
    CannotSerialize,
    CannotDeserialize,
}

impl Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}
