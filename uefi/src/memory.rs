use alloc::boxed::Box;
use alloc::vec;

use cortex_a::asm::barrier;
use cortex_a::registers::*;
use tock_registers::interfaces::Writeable;
use tock_registers::interfaces::Readable;
use tock_registers::interfaces::ReadWriteable;

/*use platform::MappingOptions;
use platform::Memory;
use platform::Mapping;
use platform::MemoryManager;*/

pub const PAGE_BITS: usize = 12;
pub const PAGE_SIZE: usize = 1 << PAGE_BITS;
pub const PAGE_MASK: usize = PAGE_SIZE - 1;

pub const TABLE_BITS: usize = 9;
pub const TABLE_SIZE: usize = 1 << TABLE_BITS;
pub const TABLE_MASK: usize = TABLE_SIZE - 1;

const PAGE_ADDRESS_MASK: u64 = (TABLE_MASK as u64) << shifter(0)
                             | (TABLE_MASK as u64) << shifter(1)
                             | (TABLE_MASK as u64) << shifter(2)
                             | (TABLE_MASK as u64) << shifter(3);

const NINE_1: u64 = 0x1FF;

const fn shifter(level: usize) -> usize {
    PAGE_BITS + TABLE_BITS * (3 - level)
}

fn encode_address(l0: u64, l1: u64, l2: u64, l3: u64, offset: u64) -> u64 {
    assert!(l0 < (TABLE_SIZE as u64));
    assert!(l1 < (TABLE_SIZE as u64));
    assert!(l2 < (TABLE_SIZE as u64));
    assert!(l3 < (TABLE_SIZE as u64));
    assert!(offset < (PAGE_SIZE as u64));
    offset | (l3 << shifter(3)) | (l2 << shifter(2)) | (l1 << shifter(1)) | (l0 << shifter(0))
}

fn decode_address(virt_addr: u64) -> (u64, u64, u64, u64, u64) {
    let offset = virt_addr & (PAGE_MASK as u64);
    let l3 = (virt_addr >> shifter(3)) & (TABLE_MASK as u64);
    let l2 = (virt_addr >> shifter(2)) & (TABLE_MASK as u64);
    let l1 = (virt_addr >> shifter(1)) & (TABLE_MASK as u64);
    let l0 = (virt_addr >> shifter(0)) & (TABLE_MASK as u64);
    (l0, l1, l2, l3, offset)
}

enum TableIndex {
    Level0,
    Level1(u64),
    Level2(u64, u64),
    Level3(u64, u64, u64),
}

impl TableIndex {
    /// only works under recursive paging
    pub fn virtual_address(self, offset: u64) -> u64 {
        match self {
            TableIndex::Level0 => encode_address(NINE_1, NINE_1, NINE_1, NINE_1, offset),
            TableIndex::Level1(l0) => encode_address(NINE_1, NINE_1, NINE_1, l0, offset),
            TableIndex::Level2(l0, l1) => encode_address(NINE_1, NINE_1, l0, l1, offset),
            TableIndex::Level3(l0, l1, l2) => encode_address(NINE_1, l0, l1, l2, offset),
        }
    }
}

fn table_descriptor(addr: u64) -> u64 {
    assert_eq!(addr & !PAGE_ADDRESS_MASK, 0);
    addr | 0b11
}

// makes writeable, executable page entries
fn block_descriptor(addr: u64) -> u64 {
    assert_eq!(addr & !PAGE_ADDRESS_MASK, 0);
    addr | 0b11 | (1 << 10)
}

fn slot_available(slot: u64) -> bool {
    (slot & 0b1) == 0
}

pub fn disable_mmu() {
    SCTLR_EL1.modify(SCTLR_EL1::M::Disable);
    unsafe { barrier::isb(barrier::SY) };
}

pub fn enable_mmu() {
    SCTLR_EL1.modify(SCTLR_EL1::M::Enable);
    unsafe { barrier::isb(barrier::SY) };
    unsafe { core::arch::asm!("mov x1, #0xbeef") };
}

pub fn debug_table(addr: *mut u64, level: usize) {
    for i in 0..TABLE_SIZE {
        unsafe {
            let slot = addr.add(i).as_mut().unwrap();
            if !slot_available(*slot) {
                let next = (*slot & PAGE_ADDRESS_MASK) as *mut u64;
                if level == 3 {
                    // log::info!("phys: 0x{:x}", next as u64);
                } else {
                    let prefix = &"            "[..(4 * level)];
                    log::info!("{}{} => table: 0x{:x}", prefix, i, next as u64);
                    debug_table(next, level + 1);
                }
            }
        }
    }
}

#[derive(Clone)]
pub struct Aarch64MemoryManager {
    l0_table: *mut u64,

    // this is either zero (no free memory)
    // or it points to a free page. when a
    // page is required, we pop this address,
    // and we replace the value of this field
    // with the u64 stored at the beginning of
    // the free page: it is a pointer to another
    // free page. it's a linked list. when a
    // page is freed, we store the value of
    // this field at the beginning of the page,
    // and the field is set to point to that page.
    next_free_page_addr: u64,

    active: bool,
}

impl Aarch64MemoryManager {
    pub fn new() -> Self {
        Self {
            l0_table: 0usize as *mut u64,
            next_free_page_addr: 0,
            active: false,
        }
    }

    /// Don't use this after boot services
    /// have been exited
    ///
    /// Because it uses the UEFI logger, which
    /// is unusable after boot services have been exited
    pub fn debug(&self) {
        debug_table(self.l0_table, 0);
    }

    /// MMU must be disabled!
    pub fn set_free_regions(&mut self, free: Box<[(u64, u64)]>) {
        assert_eq!(self.next_free_page_addr, 0);
        let mut next = 0;
        for (mut address, size) in free.iter() {
            for _ in 0..*size {
                unsafe {
                    let ptr = address as *mut u64;
                    *ptr = next;
                }
                next = address;
                address += PAGE_SIZE as u64;
            }
        }
        self.next_free_page_addr = next;
    }

    pub fn map<F>(
        &mut self,
        mut virt_addr: u64,
        mut phys_addr: u64,
        mut alloc_page: F,
        pages: usize
    )
        where F: FnMut() -> u64
    {
        assert!(!self.active);

        if self.l0_table.is_null() {
            self.l0_table = alloc_page() as *mut u64;
            unsafe {
                self.l0_table.write_bytes(0, TABLE_SIZE);
                // recursive paging
                let last_entry = self.l0_table.add(511).as_mut().unwrap();
                *last_entry = table_descriptor(self.l0_table as u64);
            }
        }

        for _ in 0..pages {
            let (l0, l1, l2, l3, offset) = decode_address(virt_addr);
            assert_eq!(offset, 0);
            let mut ptr = self.l0_table;
            unsafe {
                for index in [l0, l1, l2] {
                    let slot = ptr.add(index as usize).as_mut().unwrap();
                    if slot_available(*slot) {
                        let table = alloc_page() as *mut u64;
                        table.write_bytes(0, TABLE_SIZE);
                        *slot = table_descriptor(table as u64);
                    }
                    ptr = (*slot & PAGE_ADDRESS_MASK) as *mut u64;
                }

                let slot = ptr.add(l3 as usize).as_mut().unwrap();
                assert!(slot_available(*slot));
                *slot = block_descriptor(phys_addr);
            }

            virt_addr += PAGE_SIZE as u64;
            phys_addr += PAGE_SIZE as u64;
        }
    }

    pub fn configure(&mut self) {
        unsafe {
            MAIR_EL1.write(
                // Attribute 1 - Cacheable normal DRAM.
                MAIR_EL1::Attr1_Normal_Outer::WriteBack_NonTransient_ReadWriteAlloc +
                MAIR_EL1::Attr1_Normal_Inner::WriteBack_NonTransient_ReadWriteAlloc +

                // Attribute 0 - Device.
                MAIR_EL1::Attr0_Device::nonGathering_nonReordering_EarlyWriteAck,
            );

            TCR_EL1.write(
                  TCR_EL1::TBI0::Ignored
                + TCR_EL1::TBI1::Used

                + TCR_EL1::IPS::Bits_48

                + TCR_EL1::TG0::KiB_4
                + TCR_EL1::TG1::KiB_4

                + TCR_EL1::SH0::Inner
                + TCR_EL1::SH1::Inner

                + TCR_EL1::ORGN0::WriteBack_ReadAlloc_WriteAlloc_Cacheable
                + TCR_EL1::ORGN1::NonCacheable

                + TCR_EL1::IRGN0::WriteBack_ReadAlloc_WriteAlloc_Cacheable
                + TCR_EL1::IRGN1::NonCacheable

                + TCR_EL1::EPD0::EnableTTBR0Walks
                + TCR_EL1::EPD1::DisableTTBR1Walks

                + TCR_EL1::T0SZ.val(16)
                + TCR_EL1::T1SZ.val(16)

                + TCR_EL1::A1::TTBR0
                + TCR_EL1::AS::ASID8Bits,
            );

            TTBR0_EL1.set_baddr(self.l0_table as u64);
            TTBR1_EL1.set_baddr(self.l0_table as u64);

            barrier::isb(barrier::SY);
        }
    }
}
