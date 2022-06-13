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

pub trait Module {
    type Id;
    type Input<'a>;
    type Output<'a>;
    type Memory;
    type VM;
    type Error;
    fn memory(&self) -> &Self::Memory;
    fn call<'a, O, E>(&self, vm: &mut Self::VM, input: Self::Input<'a>) -> Result<O, Self::Error>
    where
        O: for<'x> TryFrom<Self::Output<'x>, Error = E>,
        Self::Error: From<E>;
}

type ModuleOf<T> = <T as VM>::Module;
type ModuleIdOf<T> = <ModuleOf<T> as Module>::Id;
type ModuleInputOf<'a, T> = <ModuleOf<T> as Module>::Input<'a>;
type ModuleOutputOf<'a, T> = <ModuleOf<T> as Module>::Output<'a>;
type ModuleErrorOf<T> = <ModuleOf<T> as Module>::Error;
type ErrorOf<T> = <T as VM>::Error;

pub trait VM {
    type Module: Module<VM = Self>;
    type Error: From<ModuleErrorOf<Self>>;
    fn load(&mut self, module_id: &ModuleIdOf<Self>) -> Result<Self::Module, Self::Error>;
    fn call<'a, I, IE, OE>(
        &mut self,
        module: &Self::Module,
        input: I,
    ) -> Result<I::Output, Self::Error>
    where
        I: Input + TryInto<ModuleInputOf<'a, Self>, Error = IE>,
        I::Output: for<'x> TryFrom<ModuleOutputOf<'x, Self>, Error = OE>,
        ErrorOf<Self>: From<IE>,
        ModuleErrorOf<Self>: From<OE>,
    {
        let input = input.try_into()?;
        Ok(module.call::<I::Output, OE>(self, input)?)
    }
    fn call_raw<'a, I, IE, OE>(
        &mut self,
        module_id: &ModuleIdOf<Self>,
        input: I,
    ) -> Result<I::Output, Self::Error>
    where
        I: Input + TryInto<ModuleInputOf<'a, Self>, Error = IE>,
        I::Output: for<'x> TryFrom<ModuleOutputOf<'x, Self>, Error = OE>,
        ErrorOf<Self>: From<IE>,
        ModuleErrorOf<Self>: From<OE>,
    {
        let module = self.load(module_id)?;
        let input = input.try_into()?;
        Ok(module.call::<I::Output, OE>(self, input)?)
    }
}
