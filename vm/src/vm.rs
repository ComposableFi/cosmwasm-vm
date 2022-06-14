// vm.rs ---

// Copyright (C) 2022 Hussein Ait-Lahcen

// Author: Hussein Ait-Lahcen <hussein.aitlahcen@gmail.com>

// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.

// Except as contained in this notice, the name(s) of the above copyright
// holders shall not be used in advertising or otherwise to promote the sale,
// use or other dealings in this Software without prior written authorization.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

use crate::input::Input;

pub type VmInputOf<'a, T> = <T as VM>::Input<'a>;
pub type VmOutputOf<'a, T> = <T as VM>::Output<'a>;
pub type VmErrorOf<T> = <T as VM>::Error;

pub trait VM {
    type Input<'a>;
    type Output<'a>;
    type Error;
    type Code<'a>;
    fn load<'a>(code: Self::Code<'a>) -> Result<Self, Self::Error>
    where
        Self: Sized;
    fn call<'a, I, IE, OE>(&mut self, input: I) -> Result<I::Output, Self::Error>
    where
        I: Input + TryInto<VmInputOf<'a, Self>, Error = IE>,
        I::Output: for<'x> TryFrom<VmOutputOf<'x, Self>, Error = OE>,
        VmErrorOf<Self>: From<IE> + From<OE>,
    {
        let input = input.try_into()?;
        Ok(self.raw_call::<I::Output, OE>(input)?)
    }
    fn raw_call<'a, O, E>(&mut self, input: Self::Input<'a>) -> Result<O, Self::Error>
    where
        O: for<'x> TryFrom<Self::Output<'x>, Error = E>,
        Self::Error: From<E>;
}
