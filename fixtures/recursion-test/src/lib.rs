/// Malicious test contract causing infinite recursion when host tries to
/// allocate buffers.
///
/// See semantic::test_recursion.
extern crate alloc;

extern "C" {
    fn addr_validate(source_ptr: u32) -> u32;
}

#[no_mangle]
extern "C" fn allocate(size: usize) -> u32 {
    // Call to addr_validate causes infinite recursion when host function tries
    // to call allocate to make space for the output buffer.
    let addr_ptr = release_buffer(b"bogus".to_vec());
    let ret_ptr = unsafe { addr_validate(addr_ptr) };
    consume_buffer(ret_ptr);

    release_buffer(Vec::with_capacity(size))
}

#[no_mangle]
extern "C" fn deallocate(pointer: u32) {
    consume_buffer(pointer);
}

#[repr(C)]
struct Region {
    offset: u32,
    capacity: u32,
    length: u32,
}

fn release_buffer(vec: Vec<u8>) -> u32 {
    let offset = u32::try_from(vec.as_ptr() as usize).unwrap();
    let length = u32::try_from(vec.len()).unwrap();
    let capacity = u32::try_from(vec.capacity()).unwrap();
    let region = Box::new(Region {
        offset,
        length,
        capacity,
    });
    core::mem::forget(vec);
    u32::try_from(Box::into_raw(region) as usize).unwrap()
}

fn consume_buffer(ptr: u32) -> Vec<u8> {
    unsafe {
        let region = Box::from_raw(ptr as usize as *mut Region);
        Vec::from_raw_parts(
            region.offset as *mut u8,
            usize::try_from(region.length).unwrap(),
            usize::try_from(region.capacity).unwrap(),
        )
    }
}

#[no_mangle]
extern "C" fn instantiate(env: u32, info: u32, msg: u32) -> u32 {
    consume_buffer(env);
    consume_buffer(info);
    consume_buffer(msg);
    let res = br#"{"ok":{"messages":[],"attributes":[],"events":[],"data":null}}"#;
    release_buffer(res.to_vec())
}
