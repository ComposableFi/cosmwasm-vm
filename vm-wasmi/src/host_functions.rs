#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]
use super::{
    AsContextMut, String, Tagged, ToString, VMBase, Vec, VmErrorOf, VmGas, VmQueryCustomOf,
    WasmiBaseVM, WasmiVM,
};

#[cfg(feature = "iterator")]
use super::WasmiVMError;

#[cfg(feature = "iterator")]
use cosmwasm_std::Order;
use cosmwasm_std::QueryRequest;
use cosmwasm_vm::{
    executor::{
        constants, marshall_out, passthrough_in, passthrough_in_to, passthrough_out,
        ConstantReadLimit,
    },
    system::cosmwasm_system_query_raw,
};
use wasmi::{core::Trap, Caller, Func, Linker};

/// Reads the value with the given key from the db.
///
/// Returns the pointer to the read value if a value is successfully read.
/// Returns `0` if `None` is returned from the VM.
/// Propogates the error otherwise.
pub fn env_db_read<V, S>(mut vm: WasmiVM<V, S>, key_pointer: i32) -> Result<i32, VmErrorOf<V>>
where
    V: WasmiBaseVM,
    S: AsContextMut<UserState = V>,
{
    log::debug!("db_read");

    let key = passthrough_out::<WasmiVM<V, S>, ConstantReadLimit<{ constants::MAX_LENGTH_DB_KEY }>>(
        &vm,
        key_pointer as u32,
    )?;
    let value = vm.0.as_context_mut().data_mut().db_read(key);
    match value {
        Ok(Some(value)) => {
            let Tagged(value_pointer, _) = passthrough_in::<WasmiVM<V, S>, ()>(&mut vm, &value)?;
            Ok(value_pointer as i32)
        }
        // None value is not treated as error but instead, `0` acting as nullptr is passed.
        Ok(None) => Ok(0),
        Err(e) => Err(e),
    }
}

/// Writes the given key-value pair to the db.
pub fn env_db_write<V, S>(
    mut vm: WasmiVM<V, S>,
    key_pointer: i32,
    value_pointer: i32,
) -> Result<(), VmErrorOf<V>>
where
    V: WasmiBaseVM,
    S: AsContextMut<UserState = V>,
{
    log::debug!("db_write");
    let key = passthrough_out::<WasmiVM<V, S>, ConstantReadLimit<{ constants::MAX_LENGTH_DB_KEY }>>(
        &vm,
        key_pointer as u32,
    )?;
    let value = passthrough_out::<
        WasmiVM<V, S>,
        ConstantReadLimit<{ constants::MAX_LENGTH_DB_VALUE }>,
    >(&vm, value_pointer as u32)?;
    vm.db_write(key, value)?;
    Ok(())
}

/// Removes the entry with the given key from the db.
pub fn env_db_remove<V, S>(mut vm: WasmiVM<V, S>, key_pointer: i32) -> Result<(), VmErrorOf<V>>
where
    V: WasmiBaseVM,
    S: AsContextMut<UserState = V>,
{
    log::debug!("db_remove");
    let key = passthrough_out::<WasmiVM<V, S>, ConstantReadLimit<{ constants::MAX_LENGTH_DB_KEY }>>(
        &vm,
        key_pointer as u32,
    )?;
    vm.db_remove(key)?;
    Ok(())
}

/// Creates an iterator over a storage with the given boundaries and order.
///
/// Returns the iterator id if success, otherwise the error is propogated.
#[cfg(feature = "iterator")]
pub fn env_db_scan<V, S>(
    mut vm: WasmiVM<V, S>,
    start_ptr: i32,
    end_ptr: i32,
    order: i32,
) -> Result<i32, VmErrorOf<V>>
where
    V: WasmiBaseVM,
    S: AsContextMut<UserState = V>,
{
    log::debug!("db_scan");
    let start = passthrough_out::<
        WasmiVM<V, S>,
        ConstantReadLimit<{ constants::MAX_LENGTH_DB_KEY }>,
    >(&vm, start_ptr as u32)?;
    let end = passthrough_out::<WasmiVM<V, S>, ConstantReadLimit<{ constants::MAX_LENGTH_DB_KEY }>>(
        &vm,
        end_ptr as u32,
    )?;
    let order: Order = TryInto::<Order>::try_into(order).map_err(|_| WasmiVMError::InvalidValue)?;
    let value = vm.db_scan(
        if start.is_empty() { None } else { Some(start) },
        if end.is_empty() { None } else { Some(end) },
        order,
    )?;
    Ok(value as i32)
}

/// Reads the next item in an iterator with the given iterator id.
///
/// TODO(aeryz): Check the `None` case here
#[cfg(feature = "iterator")]
pub fn env_db_next<V, S>(mut vm: WasmiVM<V, S>, iterator_id: i32) -> Result<i32, VmErrorOf<V>>
where
    V: WasmiBaseVM,
    S: AsContextMut<UserState = V>,
{
    log::debug!("db_next");
    let next = vm.db_next(iterator_id as u32);
    match next {
        Ok((key, value)) => {
            let out_data = encode_sections(&[key, value]).ok_or(WasmiVMError::InvalidValue)?;
            let Tagged(value_pointer, _) = passthrough_in::<WasmiVM<V, S>, ()>(&mut vm, &out_data)?;
            Ok(value_pointer as i32)
        }
        Err(e) => Err(e),
    }
}

/// Validates the address.
///
/// Returns `0` if the address is valid, otherwise pointer to the error string.
/// Returns `Err`, only if anything goes wrong internally.
pub fn env_addr_validate<V, S>(
    mut vm: WasmiVM<V, S>,
    address_pointer: i32,
) -> Result<i32, VmErrorOf<V>>
where
    V: WasmiBaseVM,
    S: AsContextMut<UserState = V>,
{
    log::debug!("addr_validate");
    let address = passthrough_out::<
        WasmiVM<V, S>,
        ConstantReadLimit<{ constants::MAX_LENGTH_HUMAN_ADDRESS }>,
    >(&vm, address_pointer as u32)?;

    let address = match String::from_utf8(address) {
        Ok(address) => address,
        Err(e) => {
            let Tagged(value_pointer, _) =
                passthrough_in::<WasmiVM<V, S>, ()>(&mut vm, e.to_string().as_bytes())?;
            return Ok(value_pointer as i32);
        }
    };

    match vm.addr_validate(&address)? {
        Ok(_) => Ok(0),
        Err(e) => {
            let Tagged(value_pointer, _) =
                passthrough_in::<WasmiVM<V, S>, ()>(&mut vm, e.to_string().as_bytes())?;
            Ok(value_pointer as i32)
        }
    }
}

/// Canonicalizes the address.
///
/// Writes the canonicalized address to `destination_ptr`.
/// Returns `0` if the operation is successfull, otherwise pointer to the error string.
/// Returns `Err`, only if anything goes wrong internally.
pub fn env_addr_canonicalize<V, S>(
    mut vm: WasmiVM<V, S>,
    address_ptr: i32,
    destination_ptr: i32,
) -> Result<i32, VmErrorOf<V>>
where
    V: WasmiBaseVM,
    S: AsContextMut<UserState = V>,
{
    log::debug!("addr_canonicalize");
    let address = passthrough_out::<
        WasmiVM<V, S>,
        ConstantReadLimit<{ constants::MAX_LENGTH_HUMAN_ADDRESS }>,
    >(&vm, address_ptr as u32)?;

    let address = match String::from_utf8(address) {
        Ok(address) => address,
        Err(e) => {
            let Tagged(value_pointer, _) =
                passthrough_in::<WasmiVM<V, S>, ()>(&mut vm, e.to_string().as_bytes())?;
            return Ok(value_pointer as i32);
        }
    };

    match vm.addr_canonicalize(&address)? {
        Ok(canonical_address) => {
            passthrough_in_to::<WasmiVM<V, S>>(
                &mut vm,
                destination_ptr as u32,
                &canonical_address.into(),
            )?;
            Ok(0)
        }
        Err(e) => {
            let Tagged(value_pointer, _) =
                passthrough_in::<WasmiVM<V, S>, ()>(&mut vm, e.to_string().as_bytes())?;
            Ok(value_pointer as i32)
        }
    }
}

/// Humanizes a canonical address.
///
/// Writes the humanized address to `destination_ptr`.
/// Returns `0`, if the operation is successfull, otherwise pointer to the error string.
/// Returns `Err`, only if anything goes wrong internally.
pub fn env_addr_humanize<V, S>(
    mut vm: WasmiVM<V, S>,
    address_ptr: i32,
    destination_ptr: i32,
) -> Result<i32, VmErrorOf<V>>
where
    V: WasmiBaseVM,
    S: AsContextMut<UserState = V>,
{
    log::debug!("addr_humanize");
    let address = passthrough_out::<
        WasmiVM<V, S>,
        ConstantReadLimit<{ constants::MAX_LENGTH_CANONICAL_ADDRESS }>,
    >(&vm, address_ptr as u32)?;

    // TODO(aeryz): check if `address.try_into` failure should return `Err` or `Ok(error str)`
    match vm.addr_humanize(&address.try_into()?)? {
        Ok(address) => {
            passthrough_in_to::<WasmiVM<V, S>>(
                &mut vm,
                destination_ptr as u32,
                address.into().as_bytes(),
            )?;
            Ok(0)
        }
        Err(e) => {
            let Tagged(value_pointer, _) =
                passthrough_in::<WasmiVM<V, S>, ()>(&mut vm, e.to_string().as_bytes())?;
            Ok(value_pointer as i32)
        }
    }
}

/// Verifies `secp256k1` signature with the given public key and message hash.
///
/// Returns `0` if success, otherwise `1`.
pub fn env_secp256k1_verify<V, S>(
    mut vm: WasmiVM<V, S>,
    message_hash_ptr: i32,
    signature_ptr: i32,
    public_key_ptr: i32,
) -> Result<i32, VmErrorOf<V>>
where
    V: WasmiBaseVM,
    S: AsContextMut<UserState = V>,
{
    let message_hash = passthrough_out::<
        WasmiVM<V, S>,
        ConstantReadLimit<{ constants::MAX_LENGTH_MESSAGE_HASH }>,
    >(&vm, message_hash_ptr as u32)?;
    let signature = passthrough_out::<
        WasmiVM<V, S>,
        ConstantReadLimit<{ constants::EDCSA_SIGNATURE_LENGTH }>,
    >(&vm, signature_ptr as u32)?;
    let public_key = passthrough_out::<
        WasmiVM<V, S>,
        ConstantReadLimit<{ constants::MAX_LENGTH_EDCSA_PUBKEY_LENGTH }>,
    >(&vm, public_key_ptr as u32)?;

    let result = vm.secp256k1_verify(&message_hash, &signature, &public_key)?;

    Ok(i32::from(!result))
}

/// Recovers `secp256k1` public key from message hash, signature and recovery parameter.
///
/// Returns 64 bit integer.
/// Returns the pointer to the recovered public key in the lower 32 bits, upper 32 bits MUST
/// be `0`.
/// Returns the error code in the upper 32 bits. Lower 32 bits MUST be `0`.
pub fn env_secp256k1_recover_pubkey<V, S>(
    mut vm: WasmiVM<V, S>,
    message_hash_ptr: i32,
    signature_ptr: i32,
    recovery_param: i32,
) -> Result<i64, VmErrorOf<V>>
where
    V: WasmiBaseVM,
    S: AsContextMut<UserState = V>,
{
    log::debug!("secp256k1_recover_pubkey");
    let message_hash = passthrough_out::<
        WasmiVM<V, S>,
        ConstantReadLimit<{ constants::MAX_LENGTH_MESSAGE_HASH }>,
    >(&vm, message_hash_ptr as u32)?;
    let signature = passthrough_out::<
        WasmiVM<V, S>,
        ConstantReadLimit<{ constants::EDCSA_SIGNATURE_LENGTH }>,
    >(&vm, signature_ptr as u32)?;

    if let Ok(pubkey) =
        vm.secp256k1_recover_pubkey(&message_hash, &signature, recovery_param as u8)?
    {
        // Note that if the call is success, the pointer is written to the lower
        // 4-bytes. On failure, the error code is written to the upper 4-bytes, and
        // we don't return an error.
        let Tagged(value_pointer, _) = passthrough_in::<WasmiVM<V, S>, ()>(&mut vm, &pubkey)?;
        Ok(i64::from(value_pointer))
    } else {
        // TODO(aeryz): Check for the other error codes and see if it is doable. It's good to be
        // consistent with the error codes.
        const GENERIC_ERROR_CODE: i64 = 10;
        Ok(GENERIC_ERROR_CODE << 32)
    }
}

/// Verifies `ed25519` signature with the given public key and message.
///
/// Returns `0` if success, otherwise `1`.
pub fn env_ed25519_verify<V, S>(
    mut vm: WasmiVM<V, S>,
    message_ptr: i32,
    signature_ptr: i32,
    public_key_ptr: i32,
) -> Result<i32, VmErrorOf<V>>
where
    V: WasmiBaseVM,
    S: AsContextMut<UserState = V>,
{
    log::debug!("ed25519_verify");
    let message = passthrough_out::<
        WasmiVM<V, S>,
        ConstantReadLimit<{ constants::MAX_LENGTH_ED25519_MESSAGE }>,
    >(&vm, message_ptr as u32)?;
    let signature = passthrough_out::<
        WasmiVM<V, S>,
        ConstantReadLimit<{ constants::MAX_LENGTH_ED25519_SIGNATURE }>,
    >(&vm, signature_ptr as u32)?;
    let public_key = passthrough_out::<
        WasmiVM<V, S>,
        ConstantReadLimit<{ constants::EDDSA_PUBKEY_LENGTH }>,
    >(&vm, public_key_ptr as u32)?;

    vm.ed25519_verify(&message, &signature, &public_key)
        .map(|result| i32::from(!result))
}

/// Does batch verification on `ed25519` signatures.
///
/// Returns `0` if success, otherwise `1`.
pub fn env_ed25519_batch_verify<V, S>(
    mut vm: WasmiVM<V, S>,
    messages_ptr: i32,
    signatures_ptr: i32,
    public_keys_ptr: i32,
) -> Result<i32, VmErrorOf<V>>
where
    V: WasmiBaseVM,
    S: AsContextMut<UserState = V>,
{
    // &[&[u8]]'s are written to the memory in an flattened encoded way. That's why we
    // read a flat memory, not iterate through pointers and read arbitrary memory
    // locations.
    let messages = passthrough_out::<
        WasmiVM<V, S>,
        ConstantReadLimit<
            { (constants::MAX_LENGTH_ED25519_MESSAGE + 4) * constants::MAX_COUNT_ED25519_BATCH },
        >,
    >(&vm, messages_ptr as u32)?;
    let signatures = passthrough_out::<
        WasmiVM<V, S>,
        ConstantReadLimit<
            { (constants::MAX_LENGTH_ED25519_SIGNATURE + 4) * constants::MAX_COUNT_ED25519_BATCH },
        >,
    >(&vm, signatures_ptr as u32)?;
    let public_keys = passthrough_out::<
        WasmiVM<V, S>,
        ConstantReadLimit<
            { (constants::EDDSA_PUBKEY_LENGTH + 4) * constants::MAX_COUNT_ED25519_BATCH },
        >,
    >(&vm, public_keys_ptr as u32)?;

    let (messages, signatures, public_keys) = (
        decode_sections(&messages),
        decode_sections(&signatures),
        decode_sections(&public_keys),
    );

    vm.ed25519_batch_verify(&messages, &signatures, &public_keys)
        .map(|result| i32::from(!result))
}

/// Logs the message.
pub fn env_debug<V, S>(mut vm: WasmiVM<V, S>, message_ptr: i32) -> Result<(), VmErrorOf<V>>
where
    V: WasmiBaseVM,
    S: AsContextMut<UserState = V>,
{
    let message: Vec<u8> = passthrough_out::<
        WasmiVM<V, S>,
        ConstantReadLimit<{ constants::MAX_LENGTH_ABORT }>,
    >(&vm, message_ptr as u32)?;
    vm.debug(message)?;
    Ok(())
}

/// Reads a JSON query request and does a raw query.
///
/// Returns the pointer to the result if success, otherwise propogates the error.
pub fn env_query_chain<V, S>(mut vm: WasmiVM<V, S>, query_ptr: i32) -> Result<i32, VmErrorOf<V>>
where
    V: WasmiBaseVM,
    S: AsContextMut<UserState = V>,
{
    log::debug!("query_chain");
    let request =
        marshall_out::<WasmiVM<V, S>, QueryRequest<VmQueryCustomOf<V>>>(&vm, query_ptr as u32)?;
    let value = cosmwasm_system_query_raw::<WasmiVM<V, S>>(&mut vm, request)?;
    let Tagged(value_pointer, _) = passthrough_in::<WasmiVM<V, S>, ()>(&mut vm, &value)?;
    Ok(value_pointer as i32)
}

/// Aborts the execution with the given message.
pub fn env_abort<V, S>(mut vm: WasmiVM<V, S>, message_ptr: i32) -> Result<(), VmErrorOf<V>>
where
    V: WasmiBaseVM,
    S: AsContextMut<UserState = V>,
{
    let message: Vec<u8> = passthrough_out::<
        WasmiVM<V, S>,
        ConstantReadLimit<{ constants::MAX_LENGTH_ABORT }>,
    >(&vm, message_ptr as u32)?;
    vm.abort(String::from_utf8_lossy(&message).into())?;
    Ok(())
}

/// Charges `value` amount of gas.
pub fn env_gas<V, S>(mut vm: WasmiVM<V, S>, value: i64) -> Result<(), VmErrorOf<V>>
where
    V: WasmiBaseVM,
    S: AsContextMut<UserState = V>,
{
    vm.charge(VmGas::Instrumentation {
        metered: value as u32,
    })?;
    Ok(())
}

/// Encodes multiple sections of data into one vector.
///
/// Each section is suffixed by a section length encoded as big endian uint32.
/// Using suffixes instead of prefixes allows reading sections in reverse order,
/// such that the first element does not need to be re-allocated if the contract's
/// data structure supports truncation (such as a Rust vector).
///
/// The resulting data looks like this:
///
/// ```ignore
/// section1 || section1_len || section2 || section2_len || section3 || section3_len || …
/// ```
#[cfg(feature = "iterator")]
#[must_use]
fn encode_sections(sections: &[Vec<u8>]) -> Option<Vec<u8>> {
    let out_len: usize =
        sections.iter().map(alloc::vec::Vec::len).sum::<usize>() + 4 * sections.len();
    sections
        .iter()
        .fold(Some(Vec::with_capacity(out_len)), |acc, section| {
            acc.and_then(|mut acc| {
                TryInto::<u32>::try_into(section.len())
                    .map(|section_len| {
                        acc.extend(section);
                        acc.extend_from_slice(&section_len.to_be_bytes());
                        acc
                    })
                    .ok()
            })
        })
}

/// Decodes sections of data into multiple slices.
///
/// Each encoded section is suffixed by a section length, encoded as big endian uint32.
///
/// See also: `encode_section`.
#[must_use]
fn decode_sections(data: &[u8]) -> Vec<&[u8]> {
    let mut result: Vec<&[u8]> = Vec::new();
    let mut remaining_len = data.len();
    while remaining_len >= 4 {
        let tail_len = u32::from_be_bytes([
            data[remaining_len - 4],
            data[remaining_len - 3],
            data[remaining_len - 2],
            data[remaining_len - 1],
        ]) as usize;
        result.push(&data[remaining_len - 4 - tail_len..remaining_len - 4]);
        remaining_len -= 4 + tail_len;
    }
    result.reverse();
    result
}

#[allow(clippy::too_many_lines)]
pub(crate) fn define<V: WasmiBaseVM>(
    mut ctx: impl AsContextMut<UserState = V>,
    linker: &mut Linker<V>,
) -> Result<(), VmErrorOf<V>> {
    linker
        .define(
            "env",
            "db_read",
            Func::wrap(
                ctx.as_context_mut(),
                |caller: Caller<'_, V>, param: i32| -> Result<i32, Trap> {
                    env_db_read(WasmiVM(caller), param).map_err(Into::into)
                },
            ),
        )
        .map_err(Into::<wasmi::Error>::into)?;
    linker
        .define(
            "env",
            "db_write",
            Func::wrap(
                ctx.as_context_mut(),
                |caller: Caller<'_, V>, key_pointer: i32, value_pointer: i32| -> Result<(), Trap> {
                    env_db_write(WasmiVM(caller), key_pointer, value_pointer).map_err(Into::into)
                },
            ),
        )
        .map_err(Into::<wasmi::Error>::into)?;
    linker
        .define(
            "env",
            "db_remove",
            Func::wrap(
                ctx.as_context_mut(),
                |caller: Caller<'_, V>, key_pointer: i32| -> Result<(), Trap> {
                    env_db_remove(WasmiVM(caller), key_pointer).map_err(Into::into)
                },
            ),
        )
        .map_err(Into::<wasmi::Error>::into)?;
    #[cfg(feature = "iterator")]
    linker
        .define(
            "env",
            "db_scan",
            Func::wrap(
                ctx.as_context_mut(),
                |caller: Caller<'_, V>,
                 start_ptr: i32,
                 end_ptr: i32,
                 order: i32|
                 -> Result<i32, Trap> {
                    env_db_scan(WasmiVM(caller), start_ptr, end_ptr, order).map_err(Into::into)
                },
            ),
        )
        .map_err(Into::<wasmi::Error>::into)?;
    #[cfg(feature = "iterator")]
    linker
        .define(
            "env",
            "db_next",
            Func::wrap(
                ctx.as_context_mut(),
                |caller: Caller<'_, V>, iterator_id: i32| -> Result<i32, Trap> {
                    env_db_next(WasmiVM(caller), iterator_id).map_err(Into::into)
                },
            ),
        )
        .map_err(Into::<wasmi::Error>::into)?;
    linker
        .define(
            "env",
            "addr_validate",
            Func::wrap(
                ctx.as_context_mut(),
                |caller: Caller<'_, V>, address_ptr: i32| -> Result<i32, Trap> {
                    env_addr_validate(WasmiVM(caller), address_ptr).map_err(Into::into)
                },
            ),
        )
        .map_err(Into::<wasmi::Error>::into)?;
    linker
        .define(
            "env",
            "addr_canonicalize",
            Func::wrap(
                ctx.as_context_mut(),
                |caller: Caller<'_, V>,
                 address_ptr: i32,
                 destination_ptr: i32|
                 -> Result<i32, Trap> {
                    env_addr_canonicalize(WasmiVM(caller), address_ptr, destination_ptr)
                        .map_err(Into::into)
                },
            ),
        )
        .map_err(Into::<wasmi::Error>::into)?;
    linker
        .define(
            "env",
            "addr_humanize",
            Func::wrap(
                ctx.as_context_mut(),
                |caller: Caller<'_, V>,
                 address_ptr: i32,
                 destination_ptr: i32|
                 -> Result<i32, Trap> {
                    env_addr_humanize(WasmiVM(caller), address_ptr, destination_ptr)
                        .map_err(Into::into)
                },
            ),
        )
        .map_err(Into::<wasmi::Error>::into)?;
    linker
        .define(
            "env",
            "secp256k1_verify",
            Func::wrap(
                ctx.as_context_mut(),
                |caller: Caller<'_, V>,
                 message_hash_ptr: i32,
                 signature_ptr: i32,
                 public_key_ptr: i32|
                 -> Result<i32, Trap> {
                    env_secp256k1_verify(
                        WasmiVM(caller),
                        message_hash_ptr,
                        signature_ptr,
                        public_key_ptr,
                    )
                    .map_err(Into::into)
                },
            ),
        )
        .map_err(Into::<wasmi::Error>::into)?;
    linker
        .define(
            "env",
            "secp256k1_recover_pubkey",
            Func::wrap(
                ctx.as_context_mut(),
                |caller: Caller<'_, V>,
                 message_hash_ptr: i32,
                 signature_ptr: i32,
                 recovery_param: i32|
                 -> Result<i64, Trap> {
                    env_secp256k1_recover_pubkey(
                        WasmiVM(caller),
                        message_hash_ptr,
                        signature_ptr,
                        recovery_param,
                    )
                    .map_err(Into::into)
                },
            ),
        )
        .map_err(Into::<wasmi::Error>::into)?;
    linker
        .define(
            "env",
            "ed25519_verify",
            Func::wrap(
                ctx.as_context_mut(),
                |caller: Caller<'_, V>,
                 message_hash_ptr: i32,
                 signature_ptr: i32,
                 public_key_ptr: i32|
                 -> Result<i32, Trap> {
                    env_ed25519_verify(
                        WasmiVM(caller),
                        message_hash_ptr,
                        signature_ptr,
                        public_key_ptr,
                    )
                    .map_err(Into::into)
                },
            ),
        )
        .map_err(Into::<wasmi::Error>::into)?;
    linker
        .define(
            "env",
            "ed25519_batch_verify",
            Func::wrap(
                ctx.as_context_mut(),
                |caller: Caller<'_, V>,
                 messages_ptr: i32,
                 signatures_ptr: i32,
                 public_keys_ptr: i32|
                 -> Result<i32, Trap> {
                    env_ed25519_batch_verify(
                        WasmiVM(caller),
                        messages_ptr,
                        signatures_ptr,
                        public_keys_ptr,
                    )
                    .map_err(Into::into)
                },
            ),
        )
        .map_err(Into::<wasmi::Error>::into)?;
    linker
        .define(
            "env",
            "debug",
            Func::wrap(
                ctx.as_context_mut(),
                |caller: Caller<'_, V>, message_ptr: i32| -> Result<(), Trap> {
                    env_debug(WasmiVM(caller), message_ptr).map_err(Into::into)
                },
            ),
        )
        .map_err(Into::<wasmi::Error>::into)?;
    linker
        .define(
            "env",
            "query_chain",
            Func::wrap(
                ctx.as_context_mut(),
                |caller: Caller<'_, V>, query_ptr: i32| -> Result<i32, Trap> {
                    env_query_chain(WasmiVM(caller), query_ptr).map_err(Into::into)
                },
            ),
        )
        .map_err(Into::<wasmi::Error>::into)?;
    linker
        .define(
            "env",
            "abort",
            Func::wrap(
                ctx.as_context_mut(),
                |caller: Caller<'_, V>, message_ptr: i32| -> Result<(), Trap> {
                    env_abort(WasmiVM(caller), message_ptr).map_err(Into::into)
                },
            ),
        )
        .map_err(Into::<wasmi::Error>::into)?;
    linker
        .define(
            "env",
            "gas",
            Func::wrap(
                ctx.as_context_mut(),
                |caller: Caller<'_, V>, value: i64| -> Result<(), Trap> {
                    env_gas(WasmiVM(caller), value).map_err(Into::into)
                },
            ),
        )
        .map_err(Into::<wasmi::Error>::into)?;
    Ok(())
}
