// executor.rs ---

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

use crate::{
    input::{Input, OutputOf},
    memory::{Pointable, ReadableMemory},
    vm::{Module, VM},
};
use cosmwasm_minimal_std::WasmMsg;
use wasmi::RuntimeValue;

pub trait Environment {
    type Query: Input;
    type Error;
    fn query(query: Self::Query) -> Result<OutputOf<Self::Query>, Self::Error>;
}

type ErrorOf<T> = <T as VM>::Error;
type ModuleOf<T> = <T as VM>::Module;
type ModuleErrorOf<T> = <ModuleOf<T> as Module>::Error;
type ModuleInputOf<'a, T> = <ModuleOf<T> as Module>::Input<'a>;
type ModuleOutputOf<'a, T> = <ModuleOf<T> as Module>::Output<'a>;

pub struct AllocateInput<Pointer>(Pointer);
impl<Pointer> Input for AllocateInput<Pointer> {
    type Output = Pointer;
}

pub enum SimpleExecutorError {}
pub struct AsSimpleExecutor<T>(T);
impl<T, Pointer> AsSimpleExecutor<T>
where
    T: VM,
    Pointer: for<'x> TryFrom<ModuleOutputOf<'x, T>, Error = ModuleErrorOf<T>>,
    for<'x> ModuleOutputOf<'x, T>:
        Pointable<Pointer = Pointer> + TryInto<RuntimeValue, Error = ModuleErrorOf<T>>,
    for<'x> ModuleInputOf<'x, T>: TryFrom<AllocateInput<Pointer>, Error = ErrorOf<T>>,
{
    fn allocate<L, E>(&mut self, module: &ModuleOf<T>, len: L) -> Result<Pointer, ErrorOf<T>>
    where
        Pointer: TryFrom<L, Error = E>,
        ErrorOf<T>: From<E>,
    {
        let len_value = Pointer::try_from(len)?;
        let input = AllocateInput(len_value);
        let result = self
            .0
            .call::<AllocateInput<Pointer>, ErrorOf<T>, ModuleErrorOf<T>>(module, input)?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test() {}
}
