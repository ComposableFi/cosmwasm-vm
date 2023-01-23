use core::fmt::Display;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[allow(clippy::module_name_repetitions)]
pub enum Error {
    Network,
    CannotDecode,
    CannotSerialize,
    CannotDeserialize,
    CannotCompileWasm,
}

impl Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}
