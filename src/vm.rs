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

pub trait VM {
    type ModuleId;
    type FunctionName;
    type FunctionArgs<'a>;
    type RawOutput<'a>;
    type Error;
    fn call<'a: 'b, 'b, I, O, E>(
        &'a mut self,
        module_id: &Self::ModuleId,
        input: I,
    ) -> Result<O, Self::Error>
    where
        I: Into<(Self::FunctionName, Self::FunctionArgs<'b>)>,
        O: for<'x> TryFrom<Self::RawOutput<'x>, Error = E>,
        Self::Error: From<E>,
    {
        let (function, args) = input.into();
        Ok(self.raw_call::<O, E>(module_id, function, args)?)
    }
    fn raw_call<'a: 'b, 'b, O, E>(
        &'a mut self,
        module_id: &Self::ModuleId,
        function_name: Self::FunctionName,
        function_args: Self::FunctionArgs<'b>,
    ) -> Result<O, Self::Error>
    where
        O: for<'x> TryFrom<Self::RawOutput<'x>, Error = E>,
        Self::Error: From<E>;
}
