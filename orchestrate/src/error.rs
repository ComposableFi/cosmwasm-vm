use core::fmt::Display;

#[derive(Debug)]
#[allow(clippy::module_name_repetitions)]
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
