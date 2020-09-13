use super::external;

use dynerr::*;
use std::env::args;
use std::alloc::{
    Layout,
    Global,
    AllocRef,
    AllocInit::Zeroed,
};
use std::{mem, fmt, error};

///a custom error type
#[allow(dead_code)]
#[derive(Debug)]
enum InternalError {
    PlaceHold(u32),

}
//impl display formatting for error
impl fmt::Display for InternalError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use InternalError::*;
        match self {
            PlaceHold(i)    => write!(f, "InternalError:PlaceHold: This is a placeholder {}", i),
        }
    }
}
//impl error conversion for error
impl error::Error for InternalError {}

pub struct InternalProcess {
    pub ptr:        *mut u8,
    pub base:       u64,
    external:       external::ExternalProcess,
}

impl InternalProcess {

    ///external attach to self via winapi then creates internal pointer
    pub fn attach() -> DynResult<Self> {
        let exe = args().next().unwrap();
        let name = exe.split("\\").last().unwrap();
        let external = external::ExternalProcess::attach(name)?;
        let page = external.page_map[0].clone();
        let process = Self {
            ptr: page.BaseAddress as *mut u8,
            base: page.BaseAddress,
            external,
        };
        Ok(process)
    }

    ///uses winapi to allocate an undefined region of memory
    pub fn external_allocate(&mut self, size: usize) -> DynResult<()> {
        self.external.allocate_exact(0, size)?;
        Ok(())
    }

    ///uses winapi to allocate a defined region of memory
    pub fn external_allocate_exact(&mut self, addr: u64, size: usize) -> DynResult<()> {
        self.external.allocate_exact(addr, size)?;
        self.base = self.get_alloc_base().unwrap();
        self.reset_ptr();
        Ok(())
    }

    ///gets MemBlock that was set during last external allocation
    pub fn get_alloc(&self) -> Option<external::MemBlock>{
        self.external.allocated.clone()
    }

    ///get the base of the currently allocated block
    pub fn get_alloc_base(&self) -> Option<u64> {
        Some(self.get_alloc().as_ref()?.BaseAddress)
    }

    fn read_byte(&self) -> u8 {
        unsafe {*self.ptr}
    }

    ///reads [size] bytes at self.base+[offset]
    pub fn internal_read_offset(&mut self, offset: isize, size: usize) -> Vec<u8> {
        let mut buf = Vec::new();
        self.shift_ptr(offset);
        for _ in 0..size {
            buf.push(self.read_byte());
            self.shift_ptr(1);
        }
        self.reset_ptr();
        buf
    }

    ///sets self.base to [addr] and reads [size] bytes
    pub fn internal_set_and_read(&mut self, addr: u64, size: usize) {
        self.set_base(addr);
        self.internal_read_offset(0, size);
    }

    ///get map of memory regions
    pub fn get_page_map(&mut self) -> DynResult<Vec<external::MemBlock>> {
        self.external.get_page_map()
    }
    
    fn write_byte(&self, val: u8) {
        unsafe {*self.ptr = val}
    }

    ///writes [buf] bytes to self.base+[offset]
    pub fn internal_write_offset(&mut self, offset: isize, buf: &Vec<u8>) {
        self.shift_ptr(offset);
        for b in buf {
            self.write_byte(*b);
            self.shift_ptr(1);
        }
        self.reset_ptr();
    }

    ///sets self.base to [addr] then writes [buf] bytes
    pub fn internal_set_and_write(&mut self, addr: u64, buf: &Vec<u8>) {
        self.set_base(addr);
        self.internal_write_offset(0, buf);
    }

    ///uses winapi to write [buf] to [addr]
    pub fn external_write(&self, addr: u64, buf: &mut Vec<u8>) -> DynResult<()> {
        self.external.write_memory(addr, buf)
    }
    
    fn shift_ptr(&mut self, shift: isize) {
        self.ptr = (self.ptr as isize + shift) as *mut u8;
    }

    ///sets pointer base to [addr]
    pub fn set_base(&mut self, addr: u64) {
        self.ptr = addr as *mut u8;
        self.base = addr;
    }

    fn reset_ptr(&mut self) {
        self.ptr = self.base as *mut u8;
    }

    //Unhandled exception at 0x000001C4353000A5 in test_winapi.exe: 0xC0000005: Access violation reading location 0x000000008DD8003C.
    ///creates function pointer to self.base then executes
    pub unsafe fn internal_execution(&self) {
        let exec_data: extern "C" fn () -> ! = mem::transmute(self.base as *const u8);
        exec_data();
    }

    //Unhandled exception at 0x00000238DD0200A5 in test_winapi.exe: 0xC0000005: Access violation reading location 0x000000008DD8003C.
    ///uses assembly to redirect execution flow to self.base
    pub unsafe fn internal_jmp(&self) {
        asm!(
            "jmp {addr}", 
            addr = in(reg) self.base
        )
    }
}



///uses rusts internal allocator to allocate a block\
///returns pointer
pub fn internal_allocate(size: usize, align: usize) -> DynResult<*mut u8> {
    let ptr = Global.alloc(Layout::from_size_align(size, align)?, Zeroed)?;
    Ok(ptr.ptr.as_ptr())
}    