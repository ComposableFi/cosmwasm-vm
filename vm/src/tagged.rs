use core::marker::PhantomData;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[repr(transparent)]
pub struct Tagged<T, U>(pub T, pub PhantomData<U>);
impl<T, U> Tagged<T, U> {
    #[inline(always)]
    pub fn new(t: T) -> Self {
        Tagged(t, PhantomData)
    }
}
