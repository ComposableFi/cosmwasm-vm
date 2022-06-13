// memory.rs ---

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

pub trait Pointable {
  type Pointer;
}

pub trait ReadableMemory: Pointable {
    type Error: From<GeneralMemoryError>;
    fn read(&self, offset: Self::Pointer, buffer: &mut [u8]) -> Result<(), Self::Error>;
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum GeneralMemoryError {
    InvalidTypeSize,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct InMemory<T>(T);
impl<M: ReadableMemory, T: Sized> TryFrom<(&M, M::Pointer)> for InMemory<T> {
    type Error = M::Error;
    fn try_from((memory, offset): (&M, M::Pointer)) -> Result<Self, Self::Error> {
        let size = core::mem::size_of::<T>();
        if size == 0 {
            Err(GeneralMemoryError::InvalidTypeSize.into())
        } else {
            let mut t: T = unsafe { core::mem::zeroed() };
            let buffer =
                unsafe { core::slice::from_raw_parts_mut(&mut t as *mut T as *mut u8, size) };
            memory.read(offset, buffer)?;
            Ok(InMemory(t))
        }
    }
}

/// Private
/// https://github.com/CosmWasm/cosmwasm/blob/2a6b82875563b94ccb48513bd3512bf747843cc3/packages/vm/src/memory.rs
#[repr(C)]
#[derive(Default, Clone, Copy, Debug)]
struct Region<Pointer> {
    offset: Pointer,
    capacity: Pointer,
    length: Pointer,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct InRegion<T>(T);
impl<M: ReadableMemory, T: Sized> TryFrom<(&M, M::Pointer)> for InRegion<T> {
    type Error = M::Error;
    fn try_from((memory, pointer): (&M, M::Pointer)) -> Result<Self, Self::Error> {
        let InMemory(region) = InMemory::<Region<M::Pointer>>::try_from((memory, pointer))?;
        let InMemory(value) = InMemory::<T>::try_from((memory, region.offset))?;
        Ok(InRegion(value))
    }
}
