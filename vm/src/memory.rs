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

use alloc::vec;
use alloc::vec::Vec;
use core::fmt::Debug;
use core::marker::PhantomData;

pub type PointerOf<T> = <T as Pointable>::Pointer;
pub trait Pointable {
    type Pointer: Debug + Ord + Copy + TryFrom<usize> + TryInto<usize>;
}

#[allow(clippy::module_name_repetitions)]
pub trait ReadWriteMemory:
    ReadableMemory<Error = <Self as WritableMemory>::Error> + WritableMemory
{
}

pub type ReadableMemoryErrorOf<T> = <T as ReadableMemory>::Error;
#[allow(clippy::module_name_repetitions)]
pub trait ReadableMemory: Pointable {
    type Error: From<MemoryReadError>;
    fn read(&self, offset: Self::Pointer, buffer: &mut [u8]) -> Result<(), Self::Error>;
}

pub type WritableMemoryErrorOf<T> = <T as WritableMemory>::Error;
#[allow(clippy::module_name_repetitions)]
pub trait WritableMemory: Pointable {
    type Error: From<MemoryWriteError>;
    fn write(&self, offset: Self::Pointer, buffer: &[u8]) -> Result<(), Self::Error>;
}

pub struct Write<'a, 'b, M: Pointable>(pub &'a M, pub M::Pointer, pub &'b [u8]);
pub struct TypedWrite<'a, 'b, M: Pointable, T>(pub &'a M, pub M::Pointer, pub &'b T);
pub struct Read<'a, M: Pointable>(pub &'a M, pub M::Pointer);
pub struct LimitedRead<'a, M: Pointable>(pub &'a M, pub M::Pointer, pub M::Pointer);
pub struct LimitedTypedRead<'a, M: Pointable>(pub &'a M, pub M::Pointer, pub M::Pointer);

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[allow(clippy::module_name_repetitions)]
pub enum MemoryReadError {
    InvalidTypeSize,
    OverflowLimit,
    InvalidPointer,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[allow(clippy::module_name_repetitions)]
pub enum MemoryWriteError {
    RegionTooSmall,
    BufferSizeOverflowPointer,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(transparent)]
#[allow(clippy::module_name_repetitions)]
pub struct FromMemory<T>(pub T);
impl<'a, M, T> TryFrom<Read<'a, M>> for FromMemory<T>
where
    T: Sized,
    M: ReadableMemory,
{
    type Error = M::Error;
    fn try_from(Read(memory, offset): Read<'a, M>) -> Result<Self, Self::Error> {
        log::trace!("FromMemory");
        let size = core::mem::size_of::<T>();
        if size == 0 {
            Err(MemoryReadError::InvalidTypeSize.into())
        } else {
            let mut t: T = unsafe { core::mem::zeroed() };
            let buffer =
                unsafe { core::slice::from_raw_parts_mut(core::ptr::addr_of_mut!(t) as *mut u8, size) };
            memory.read(offset, buffer)?;
            Ok(FromMemory(t))
        }
    }
}

/// Private
/// <https://github.com/CosmWasm/cosmwasm/blob/2a6b82875563b94ccb48513bd3512bf747843cc3/packages/vm/src/memory.rs>
#[repr(C)]
#[derive(Default, Clone, Copy, Debug)]
struct Region<Pointer> {
    offset: Pointer,
    capacity: Pointer,
    length: Pointer,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct FromRegion<T>(pub T);
impl<'a, M, T> TryFrom<LimitedTypedRead<'a, M>> for FromRegion<T>
where
    T: Sized,
    M: ReadableMemory,
{
    type Error = M::Error;
    fn try_from(
        LimitedTypedRead(memory, pointer, limit): LimitedTypedRead<'a, M>,
    ) -> Result<Self, Self::Error> {
        log::trace!("FromRegion");
        let FromMemory(region) = FromMemory::<Region<M::Pointer>>::try_from(Read(memory, pointer))?;
        if region.length > limit {
            Err(MemoryReadError::OverflowLimit.into())
        } else {
            let FromMemory(value) = FromMemory::<T>::try_from(Read(memory, region.offset))?;
            Ok(FromRegion(value))
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct RawFromRegion(pub Vec<u8>);
impl<'a, M> TryFrom<LimitedRead<'a, M>> for RawFromRegion
where
    M: ReadableMemory,
{
    type Error = M::Error;
    fn try_from(
        LimitedRead(memory, pointer, limit): LimitedRead<'a, M>,
    ) -> Result<Self, Self::Error> {
        log::trace!("RawFromRegion: {:?}", pointer);
        let FromMemory(region) = FromMemory::<Region<M::Pointer>>::try_from(Read(memory, pointer))?;
        if region.length > limit {
            Err(MemoryReadError::OverflowLimit.into())
        } else {
            let mut buffer = vec![
                0u8;
                region
                    .length
                    .try_into()
                    .map_err(|_| MemoryReadError::InvalidPointer)?
            ];
            memory.read(region.offset, &mut buffer)?;
            Ok(RawFromRegion(buffer))
        }
    }
}

#[allow(clippy::module_name_repetitions)]
pub struct RawIntoMemory;
impl<'a, 'b, M> TryFrom<Write<'a, 'b, M>> for RawIntoMemory
where
    M: WritableMemory,
{
    type Error = M::Error;
    fn try_from(Write(memory, offset, buffer): Write<'a, 'b, M>) -> Result<Self, Self::Error> {
        log::trace!("RawIntoMemory");
        memory.write(offset, buffer)?;
        Ok(RawIntoMemory)
    }
}

#[allow(clippy::module_name_repetitions)]
pub struct IntoMemory<T>(pub PhantomData<T>);
impl<'a, 'b, M, T> TryFrom<TypedWrite<'a, 'b, M, T>> for IntoMemory<T>
where
    T: Sized,
    M: WritableMemory,
{
    type Error = M::Error;
    fn try_from(
        TypedWrite(memory, offset, value): TypedWrite<'a, 'b, M, T>,
    ) -> Result<Self, Self::Error> {
        log::trace!("IntoMemory");
        let buffer = unsafe {
            core::slice::from_raw_parts((value as *const T).cast::<u8>(), core::mem::size_of::<T>())
        };
        memory.write(offset, buffer)?;
        Ok(IntoMemory(PhantomData))
    }
}

pub struct IntoRegion<T>(pub PhantomData<T>);
impl<'a, 'b, M, T> TryFrom<TypedWrite<'a, 'b, M, T>> for IntoRegion<T>
where
    T: Sized,
    M: ReadWriteMemory,
{
    type Error = <M as ReadableMemory>::Error;
    fn try_from(
        TypedWrite(memory, pointer, value): TypedWrite<'a, 'b, M, T>,
    ) -> Result<Self, Self::Error> {
        log::trace!("IntoRegion");
        let FromMemory(mut region) =
            FromMemory::<Region<M::Pointer>>::try_from(Read(memory, pointer))
                .map_err(|_| MemoryWriteError::BufferSizeOverflowPointer)?;
        log::trace!("Region: {:?}", region);
        let len = M::Pointer::try_from(core::mem::size_of::<T>())
            .map_err(|_| MemoryWriteError::BufferSizeOverflowPointer)?;
        if region.capacity < len {
            Err(<M as WritableMemory>::Error::from(
                MemoryWriteError::RegionTooSmall,
            ))
        } else {
            let _ = IntoMemory::try_from(TypedWrite(memory, region.offset, value))?;
            region.length = len;
            let _ = IntoMemory::try_from(TypedWrite(memory, pointer, &region))?;
            Ok(IntoRegion(PhantomData))
        }
    }
}

pub struct RawIntoRegion;
impl<'a, 'b, M> TryFrom<Write<'a, 'b, M>> for RawIntoRegion
where
    M: ReadWriteMemory,
{
    type Error = <M as ReadableMemory>::Error;
    fn try_from(Write(memory, pointer, value): Write<'a, 'b, M>) -> Result<Self, Self::Error> {
        log::trace!("RawIntoRegion");
        let FromMemory(mut region) =
            FromMemory::<Region<M::Pointer>>::try_from(Read(memory, pointer))
                .map_err(|_| MemoryWriteError::BufferSizeOverflowPointer)?;
        log::trace!("Region: {:?}", region);
        let len = M::Pointer::try_from(value.len())
            .map_err(|_| MemoryWriteError::BufferSizeOverflowPointer)?;
        if region.capacity < len {
            Err(<M as WritableMemory>::Error::from(
                MemoryWriteError::RegionTooSmall,
            ))
        } else {
            let _ = RawIntoMemory::try_from(Write(memory, region.offset, value))?;
            region.length = len;
            let _ = IntoMemory::try_from(TypedWrite(memory, pointer, &region))?;
            Ok(RawIntoRegion)
        }
    }
}
