#[derive(Debug)]
#[repr(C)]
pub struct MallocEvent {
    pub ptr: u64,
    pub stackid: i64,
    pub size: u64,
}

#[derive(Debug)]
#[repr(C)]
pub struct FreeEvent {
    pub ptr: u64,
}
