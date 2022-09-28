#![feature(naked_functions)]
#![feature(abi_efiapi)]
#![no_std]
#![no_main]

extern crate alloc;

mod memory;
mod interrupts;

use alloc::vec;
use alloc::vec::Vec;
use core::fmt::Write;
use core::arch::asm;
use core::str::from_utf8;

use pl011_qemu::PL011;
use pl011_qemu::UART1;

use psci::cpu_on;
use psci::error::Error::*;

use uefi_services::init;
use uefi::prelude::entry;
use uefi::Status;
use uefi::Handle;
use uefi::table::SystemTable;
use uefi::table::Boot;
use uefi::table::boot::MemoryType;

use memory::Aarch64MemoryManager;
use memory::PAGE_SIZE;

use numtoa::NumToA;

extern "C" fn inf_loop() -> ! {
    unsafe {
        asm!("mov x1, #0xbeef");
    }
    loop {}
}

fn num_to_str<T: NumToA<T>>(buffer: &mut [u8; 30], number: T, base: T) -> &str {
    from_utf8(number.numtoa(base, buffer)).unwrap()
}

#[entry]
fn main(
    handle: Handle,
    mut system_table: SystemTable<Boot>,
) -> Status {
    init(&mut system_table).unwrap();
    let bootsvc = system_table.boot_services();

    let mmap_size = bootsvc.memory_map_size();
    let mut mmap = vec![0; mmap_size.map_size + 16 * mmap_size.entry_size];

    let mut free_regions = 0;
    {
        let (_, layout) = bootsvc.memory_map(&mut mmap).unwrap();
        for descriptor in layout {
            if descriptor.ty == MemoryType::CONVENTIONAL {
                free_regions += 1;
            }
        }
    }
    let mut free_regions = Vec::with_capacity(free_regions);

    {
        let (_, layout) = bootsvc.memory_map(&mut mmap).unwrap();
        for descriptor in layout {
            if descriptor.ty == MemoryType::CONVENTIONAL {
                free_regions.push((descriptor.phys_start, descriptor.page_count));
            }
        }
    }

    let mut alloc_page = || {
        for (addr, count) in free_regions.iter_mut() {
            if *count > 0 {
                *count -= 1;
                let backup = *addr;
                *addr += PAGE_SIZE as u64;
                return backup;
            }
        }
        panic!("Out of memory!");
    };

    let mut mmgr = Aarch64MemoryManager::new();

    {
        let (_, layout) = bootsvc.memory_map(&mut mmap).unwrap();
        for descriptor in layout {
            if descriptor.ty != MemoryType::CONVENTIONAL {
                let count = descriptor.page_count as usize;
                // descriptor has 0 as virt_start because
                // we're in id mapping: phys and virt are eq.
                let virt_addr = descriptor.phys_start;
                let phys_addr = descriptor.phys_start;
                mmgr.map(virt_addr, phys_addr, &mut alloc_page, count);
            }
        }
    }

    log::info!("Memory map recreated");

    interrupts::setup();

    log::info!("going in");
    unsafe { asm!("svc #18") };

    let (_rtsvc, _map) = system_table.exit_boot_services(handle, &mut mmap).unwrap();

    let mut logger = PL011::new(UART1::take().unwrap());

    let _ = logger.write_str("Ahoy\r\n");

    // memory::disable_mmu();

    let _ = logger.write_str("\r\nActivating new memory map...\r\n");

    mmgr.set_free_regions(free_regions.into_boxed_slice());
    mmgr.activate();

    memory::enable_mmu();

    let _ = logger.write_str("Starting cores...\r\n");
    let mut online_cores = 1;
    for i in 0..usize::MAX {
        let ptr = inf_loop as u64;
        if let Err(kind) = cpu_on(i as u64, ptr, 0) {
            let msg = match kind {
                NotSupported => "NotSupported",
                InvalidParameters => break,
                Denied => "Denied",
                AlreadyOn => continue,
                OnPending => "OnPending",
                InternalFailure => "InternalFailure",
                NotPresent => "NotPresent",
                Disabled => "Disabled",
                InvalidAddress => "InvalidAddress",
                _ => "Unknown",
            };
            let _ = logger.write_str("Error: ");
            let _ = logger.write_str(msg);
            let _ = logger.write_str("\r\n");
        } else {
            online_cores += 1;
        }
    }

    let _ = logger.write_str("Online cores: ");
    let _ = logger.write_str(num_to_str(&mut [0u8; 30], online_cores, 10));
    let _ = logger.write_str("\r\n");

    inf_loop();
}
