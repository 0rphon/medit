#![feature(asm,allocator_api)]
pub mod external;
pub mod internal;

pub use external::ExternalProcess;
pub use internal::InternalProcess;




#[cfg(test)]
mod tests {
    use super::*;
    use dynerr::*;
    #[test]
    fn external_test() -> DynResult<()> {
        use std::env::args;
        let exe = args().next().unwrap();
        let name = exe.split("\\").last().unwrap();
        let mut process = ExternalProcess::attach(name)?;
        let _exe_base = process.get_base(name).unwrap();
        process.allocate(64)?;
        let alloc_base = process.allocated.as_ref().unwrap().BaseAddress;
        process.allocate_exact(alloc_base, 64)?;
        process.write_memory(alloc_base, &mut vec!(0x90;64))?;
        let read = process.read_memory(alloc_base, 64)?;
        assert_eq!(read, vec!(0x90;64));
        let map = process.get_page_map()?;
        assert_eq!(
            map.iter().any(
                |b| b.BaseAddress == process.allocated
                    .as_ref()
                    .unwrap()
                    .BaseAddress
            ), true
        );
        Ok(())
    }

    #[test]
    fn internal_test() -> DynResult<()> {
        let _internal_ptr = internal::internal_allocate(128, 16)?;

        let mut process = InternalProcess::attach()?;
        process.external_allocate(128)?;
        let map = process.get_page_map()?;
        assert_eq!(
            map.iter().any(
                |b| b.BaseAddress == process.get_alloc_base().unwrap()
            ), true
        );
        process.external_allocate_exact(process.get_alloc_base().unwrap(), 128)?;

        process.internal_write_offset(32, &mut vec!(0x90;32));
        let read = process.internal_read_offset(32, 32);
        assert_eq!(read, vec!(0x90;32));

        
        Ok(())
    }
}