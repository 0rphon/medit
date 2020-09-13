#![cfg(target_os="windows")]
use winapi::um::tlhelp32::{TH32CS_SNAPPROCESS, PROCESSENTRY32W, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32, MODULEENTRY32W, CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, Module32FirstW, Module32NextW};
use winapi::um::handleapi::{INVALID_HANDLE_VALUE, CloseHandle};
use winapi::um::processthreadsapi::{OpenProcess};
use winapi::um::winnt::{PROCESS_ALL_ACCESS, HANDLE, MEM_COMMIT, PAGE_EXECUTE_READWRITE, MEMORY_BASIC_INFORMATION};
use winapi::um::memoryapi::{ReadProcessMemory, WriteProcessMemory, VirtualAllocEx, VirtualQueryEx};
use winapi::um::errhandlingapi::GetLastError;
use winapi::shared::minwindef::{LPCVOID, LPVOID};
use winapi::shared::ntdef::NULL;
use winapi::ctypes::c_void;
use wio::wide::FromWide;
use std::mem::{zeroed, size_of, MaybeUninit};
use std::collections::HashMap;
use std::ffi::OsString;
use std::{fmt, error};
use dynerr::*;

///a custom error type
#[allow(dead_code)]
#[derive(Debug)]
enum ExternalError {
    InvalidHandleValue(u32, u32),
    NameConversionError(u32, OsString),
    ProcessNotFound(String),
    ProcessSnapshotError(String),
    ModuleSnapshotError(u32),
    OpenProcessError(u32, u32),
    BytesReadError(usize, usize, u64),
    ReadMemoryError(u64, u32),
    BytesWriteError(usize, usize, u64),
    WriteMemoryError(u64, u32),
    AllocMemoryError(u64, u32),
    MemoryQueryError(u64, u32),
    FailedToGetModules(u32),
}
//impl display formatting for error
impl fmt::Display for ExternalError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use ExternalError::*;
        match self {
            InvalidHandleValue(i, e)    => write!(f, "ExternalError::InvalidHandleValue: CreateToolhelp32Snapshot returned {}. GetLasError returned 0x{:X} (try running as admin)", i, e),
            NameConversionError(i, s)   => write!(f, "ExternalError::NameConversionError: Name conversion for {} : {:?} unsuccessful", i, s),
            ProcessNotFound(s)          => write!(f, "ExternalError::ProcessNotFound: Could not find PID for process \"{}\"",s),
            ProcessSnapshotError(s)     => write!(f, "ExternalError::SnapshotError: Failed to get first process in system snapshot. Returned {}", s),
            ModuleSnapshotError(p)      => write!(f, "ExternalError::ModuleSnapshotError: Failed to get first module in snapshot for PID {}", p),
            OpenProcessError(i, e)      => write!(f, "ExternalError::OpenProcessError: Unable to get process handle for PID {} (try running as admin). GetLastError returned 0x{:X}", i, e),
            BytesReadError(r, t, a)     => write!(f, "ExternalError::BytesReadError: Read {} bytes instead of {} bytes at 0x{:X}", r, t, a),
            ReadMemoryError(a, e)       => write!(f, "ExternalError::ReadMemoryError: Failed to read memory at 0x{:X}. GetLastError returned 0x{:X}", a, e),
            BytesWriteError(w, t, a)    => write!(f, "ExternalError::BytesReadError: Wrote {} bytes instead of {} bytes at 0x{:X}", w, t, a),
            WriteMemoryError(a, e)      => write!(f, "ExternalError::WriteMemoryError: Failed to write memory at 0x{:X}. GetLastError returned 0x{:X}", a, e),
            AllocMemoryError(a, e)      => write!(f, "ExternalError::AllocMemoryError: Failed to allocate memory at 0x{:X}. GetLastError returned 0x{:X}", a, e),
            MemoryQueryError(a, e)      => write!(f, "ExternalError::MemoryQueryError: failed to query memory at address 0x{:X}. GetLastError returned 0x{:X}", a, e),
            FailedToGetModules(p)       => write!(f, "ExternalError::FailedToGetModules: PID {} returned no modules",p),
        }
    }
}
//impl error conversion for error
impl error::Error for ExternalError {}

#[allow(non_snake_case)]
#[derive(Clone, Debug)]
pub struct MemBlock {
    pub BaseAddress:        u64,
    pub AllocationBase:     u64,
    pub AllocationProtect:  u64,
    pub RegionSize:         u64,
    pub State:              u64,
    pub Protect:            u64,
    pub Type:               u64,   
}

impl MemBlock {
    fn new(buf: MEMORY_BASIC_INFORMATION) -> Self {
        MemBlock {
            BaseAddress:        buf.BaseAddress as u64,
            AllocationBase:     buf.AllocationBase as u64,
            AllocationProtect:  buf.AllocationProtect as u64,
            RegionSize:         buf.RegionSize as u64,
            State:              buf.State as u64,
            Protect:            buf.Protect as u64,
            Type:               buf.Type as u64,   
        }
    }

    fn new_null() -> Self {
        MemBlock{
            BaseAddress:        0,
            AllocationBase:     0,
            AllocationProtect:  0,
            RegionSize:         0,
            State:              0,
            Protect:            0,
            Type:               0,
        }
    }
}



pub type BaseList = HashMap<String, u64>;
pub trait WinAPI {

    fn handle(&self) -> HANDLE;

    /// takes process name and returns corresponding process ID
    fn find_pid_by_name(name: &str) -> DynResult<u32> {
        let snap_handle = unsafe{CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)};          //DWORD dwflag TH32CS_SNAPMODULE32 and pid 0 tells api to create system snapshot of all processes
        if snap_handle == INVALID_HANDLE_VALUE {                                            //if snapshot handle == {0xffffffffffffffff as *mut ctypes::c_void}
            dynerr!(ExternalError::InvalidHandleValue(
                snap_handle as u32,
                unsafe{GetLastError()}
            ))
        }
        let mut process_entry: PROCESSENTRY32W = unsafe {zeroed()};                         //A pointer to a PROCESSENTRY32W structure required by Process32FirstW
        process_entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;                         //set dwSize to size of PROCESSENTRY32W or it will fail
    
        if let 0 = unsafe {Process32FirstW(snap_handle, &mut process_entry)} {              //takes snapshot handle, pointer to PROCESSENTRY32W struct and writes first process in snapshot to PROCESSENTRY32W struct
            unsafe {CloseHandle(snap_handle)};
            dynerr!(ExternalError::ProcessSnapshotError(name.to_string()))
        }
    
        let mut success = 1;
        while success == 1 {                                                                //iterate through process snapshot, updating process_entry data and capture return value into success
            let process_name = OsString::from_wide(&process_entry.szExeFile);               //converts process name in process_entry.szExeFile from array to ctype string
            match process_name.into_string() {                                              //convert from ctypes string into rust string
                Ok(s) => {
                    if s.replace("\u{0}","") == name {
                        unsafe {CloseHandle(snap_handle)};
                        return Ok(process_entry.th32ProcessID)
                    }
                },
                Err(s) => {
                    dynerr!(ExternalError::NameConversionError(process_entry.th32ProcessID,s))
                }
            }
            success = unsafe {Process32NextW(snap_handle, &mut process_entry)};
        }
        unsafe {CloseHandle(snap_handle)};
        dynerr!(ExternalError::ProcessNotFound(name.to_string()))
    }

    /// takes process pid and returns all module Names & BaseAddrs in target\
    /// needs admin rights
    fn get_all_module_bases(pid: u32) -> DynResult<BaseList>{
        let snap_handle = unsafe {CreateToolhelp32Snapshot(                                                 //tells api to create snapshot of 32&64 bit modules in target process
            TH32CS_SNAPMODULE|TH32CS_SNAPMODULE32,
            pid
        )};
        if snap_handle == INVALID_HANDLE_VALUE {
            dynerr!(ExternalError::InvalidHandleValue(
                snap_handle as u32,
                unsafe{GetLastError()}
            ))
        }
        let mut module_entry: MODULEENTRY32W = unsafe {zeroed()};                                           //A pointer to a MODULEENTRY32W structure required by Module32FirstW
        module_entry.dwSize = size_of::<MODULEENTRY32W>() as u32;                                           //set dwSize to size of MODULEENTRY32W or it will fail

        if let 0 = unsafe {Module32FirstW(snap_handle, &mut module_entry)} {                                //takes snapshot handle, pointer to MODULEENTRY32W struct and writes first module in snapshot to MODULEENTRY32W struct
            unsafe {CloseHandle(snap_handle)};
            dynerr!(ExternalError::ModuleSnapshotError(pid))
        }

        let mut module_bases = HashMap::new();
        let mut success = 1;
        while success == 1 {                                                                                //iterate through module snapshot, updating module_entry data and capture return value into success
            let module_name = OsString::from_wide(&module_entry.szModule);                                  //converts module name in module_entry.szModule from array to ctype string
            match module_name.into_string() {                                                               //convert from ctypes string into rust string
                Ok(s) => {
                    module_bases.insert(
                        s.replace("\u{0}",""),
                        module_entry.modBaseAddr as u64
                    );
                },
                Err(s) => {
                    dynerr!(ExternalError::NameConversionError(module_entry.th32ModuleID,s))
                }
            }
            success = unsafe {Module32NextW(snap_handle, &mut module_entry)};
        }
        unsafe {CloseHandle(snap_handle)};
        if module_bases.len() == 0 {dynerr!(ExternalError::FailedToGetModules(pid))}
        else {Ok(module_bases)}
    }

    /// gets handle to target process with all possible permissions\
    /// needs admin rights
    fn get_handle_all(pid: u32) -> DynResult<HANDLE> {
        Self::get_handle(pid, PROCESS_ALL_ACCESS)
    }

    fn get_handle(pid: u32, permissions: u32) -> DynResult<HANDLE> {
        let handle = unsafe{OpenProcess(permissions, 0, pid)};                       //takes the desired access, InheritHandle flag (false for us), and  pid. returns handle to process
        if let 0 = handle as usize {
            dynerr!(ExternalError::OpenProcessError(
                pid,
                unsafe{GetLastError()}
            ))
        }
        Ok(handle)
    }

    /// read [size] bytes at [addr] in [handle]
    fn read_memory(&self, addr: u64, size: usize) -> DynResult<Vec<u8>> {
        unsafe {
            let mut buffer = Vec::with_capacity(size);
            buffer.set_len(size);
            let mut bytes_read = MaybeUninit::uninit().assume_init();   //creates uninitalized var to capture len of bytes read
            if let 0 = ReadProcessMemory(                               //takes handle, baseaddr, buffer to write to, size, and var to write read len to
                self.handle(),
                addr as LPCVOID,
                buffer.as_mut_ptr() as *mut c_void,
                size,
                &mut bytes_read as *mut usize
            ) {dynerr!(ExternalError::ReadMemoryError(addr, GetLastError()))}
            if bytes_read != size {
                dynerr!(ExternalError::BytesReadError(bytes_read, size, addr))
            }
            Ok(buffer)
        }
    }

    /// write [buffer] at [addr] in [handle]\
    /// returns () if success
    fn write_memory(&self, addr: u64, buffer: &mut Vec<u8>) -> DynResult<()> {
        unsafe {
            let mut bytes_wrote = MaybeUninit::uninit().assume_init();  //creates uninitalized var to capture len of bytes written
            if let 0 = WriteProcessMemory(                              //takes handle, baseaddr, bytes to write, size to write, and var to return len of bytes written
                self.handle(),
                addr as LPVOID,
                buffer.as_mut_ptr() as *mut c_void,
                buffer.len(),
                &mut bytes_wrote as *mut usize
            ) {dynerr!(ExternalError::WriteMemoryError(addr, GetLastError()))}
            if bytes_wrote != buffer.len() {
                dynerr!(ExternalError::BytesWriteError(bytes_wrote, buffer.len(), addr))
            }
            Ok(())
        }
    }

    /// allocates [size] at [addr] in [handle]\
    /// if addr is 0 then the system will determine the best place to allocate\
    /// returns pointer to memory if success
    fn alloc_memory(&self, addr: u64, size: usize) -> DynResult<u64> {
        unsafe{
            let new_mem = VirtualAllocEx(
                self.handle(),
                addr as LPVOID,
                size, MEM_COMMIT,
                PAGE_EXECUTE_READWRITE
            );
            if let NULL = new_mem {
                dynerr!(ExternalError::AllocMemoryError(
                    addr,
                    GetLastError()
                ))
            }
            Ok(new_mem as u64)
        }
    }


    fn query_memory(&self, addr: u64) -> DynResult<MemBlock> {
        let mut buf: MEMORY_BASIC_INFORMATION = unsafe {zeroed()};
        let length = size_of::<MEMORY_BASIC_INFORMATION>() as usize;
        unsafe {
            if 0 == VirtualQueryEx(self.handle(), addr as LPVOID, &mut buf, length) {
                dynerr!(ExternalError::MemoryQueryError(addr, GetLastError()))
            }
        }
        let page = MemBlock::new(buf);
        Ok(page)
    }
}





pub struct ExternalProcess {
    pub pid: u32,
    base_list: BaseList,
    pub handle: HANDLE,
    pub allocated: Option<MemBlock>,
    pub page_map: Vec<MemBlock>,
}

impl ExternalProcess {
    pub fn attach(name: &str) -> DynResult<Self> {
        let pid = Self::find_pid_by_name(name)?;
        let mut block = Self {
            pid,
            base_list: Self::get_all_module_bases(pid)?,
            handle: Self::get_handle_all(pid)?,
            allocated: None,
            page_map: vec!(),
        };
        block.poll_memory()?;
        Ok(block)
    }

    ///attempts to get module base address
    pub fn get_base(&self, module: &str) -> Option<&u64> {
        self.base_list.get(module)
    }

    ///attempts to allocate an unspecified region in memory
    pub fn allocate(&mut self, size: usize) -> DynResult<()> {
        self.allocate_exact(0, size)
    }

    ///attempts to allocate an exact region in memory
    pub fn allocate_exact(&mut self, addr: u64, size: usize) -> DynResult<()> {
        let alloc_addr = self.alloc_memory(addr, size)?;
        self.allocated = Some(self.query_memory(alloc_addr)?);
        self.poll_memory()?;
        Ok(())
    }

    ///attempts to read a region in memory
    pub fn read_memory(&self, addr: u64, size: usize) -> DynResult<Vec<u8>> {
        WinAPI::read_memory(self, addr, size)
    }

    ///attempts to write to a region in memory
    pub fn write_memory(&self, addr: u64, buf: &mut Vec<u8>) -> DynResult<()> {
        WinAPI::write_memory(self, addr, buf)
    }

    ///gets memory map of allocated regions
    pub fn get_page_map(&mut self) -> DynResult<Vec<MemBlock>> {
        self.poll_memory()?;
        Ok(self.page_map.clone())
    }

    ///updates page map
    fn poll_memory(&mut self) -> DynResult<()> {
        let mut map = Vec::new();
        let mut page = MemBlock::new_null();
        loop {
            page = match self.query_memory(page.BaseAddress+page.RegionSize) {
                Ok(resp) => resp,
                Err(e)   => {
                    dynmatch!(e,
                        type ExternalError {
                            arm ExternalError::MemoryQueryError(_, 0x57) => break,
                            _ => return Err(e)
                        },
                        _ => return Err(e)
                    )
                }
            };
            map.push(page.clone());
        }
        self.page_map = map;
        Ok(())
    }
}

impl WinAPI for ExternalProcess {
    fn handle(&self) -> HANDLE {self.handle}
}




//external process
//internal process (can still do external stuff)

//extern trait
//intern trait
//internal impls both
//external impls extern