use alloc::boxed::Box;
use alloc::vec;

use cortex_a::asm::barrier;
use cortex_a::registers::*;
use tock_registers::interfaces::Writeable;
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
    let offset = virt_addr & (PAGE_SIZE as u64 - 1);
    let l3 = (virt_addr >> shifter(3)) & (TABLE_SIZE as u64 - 1);
    let l2 = (virt_addr >> shifter(2)) & (TABLE_SIZE as u64 - 1);
    let l1 = (virt_addr >> shifter(1)) & (TABLE_SIZE as u64 - 1);
    let l0 = (virt_addr >> shifter(0)) & (TABLE_SIZE as u64 - 1);
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
    addr | 0b01
}

// makes writeable, executable page entries
fn block_descriptor(addr: u64) -> u64 {
    addr | 0b11
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
}

#[derive(Clone)]
pub struct Aarch64MemoryManager {
    l0_table: *mut u64,
    free: Box<[(u64, u64)]>,
    active: bool,
}

impl Aarch64MemoryManager {
    pub fn new() -> Self {
        Self {
            l0_table: 0usize as *mut u64,
            free: vec![].into_boxed_slice(),
            active: false,
        }
    }

    pub fn set_free_regions(&mut self, free: Box<[(u64, u64)]>) {
        assert_eq!(self.free.len(), 0);
        self.free = free;
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
            let (l0, l1, l2, l3, _offset) = decode_address(virt_addr);
            let indices = [l0, l1, l2, l3];
            let mut ptr = self.l0_table;
            unsafe {
                for i in 0..3 {
                    let slot = ptr.add(indices[i] as usize).as_mut().unwrap();
                    if slot_available(*slot) {
                        let table = alloc_page() as *mut u64;
                        table.write_bytes(0, TABLE_SIZE);
                        *slot = table_descriptor(table as u64);
                    }
                    ptr = (*slot & PAGE_ADDRESS_MASK) as *mut u64;
                }

                let slot = ptr.add(indices[3] as usize).as_mut().unwrap();
                assert!(slot_available(*slot));
                *slot = block_descriptor(phys_addr);
            }

            virt_addr += PAGE_SIZE as u64;
            phys_addr += PAGE_SIZE as u64;
        }
    }

    pub fn activate(&mut self) {
        unsafe {
            MAIR_EL1.write(
                // Attribute 1 - Cacheable normal DRAM.
                MAIR_EL1::Attr1_Normal_Outer::WriteBack_NonTransient_ReadWriteAlloc +
                MAIR_EL1::Attr1_Normal_Inner::WriteBack_NonTransient_ReadWriteAlloc +

                // Attribute 0 - Device.
                MAIR_EL1::Attr0_Device::nonGathering_nonReordering_EarlyWriteAck,
            );

            TTBR1_EL1.set_baddr(self.l0_table as u64);

            TCR_EL1.write(
                TCR_EL1::TBI1::Ignored
                    + TCR_EL1::IPS::Bits_52
                    + TCR_EL1::TG1::KiB_4
                    + TCR_EL1::SH1::Outer
                    + TCR_EL1::ORGN1::NonCacheable
                    + TCR_EL1::IRGN1::NonCacheable
                    + TCR_EL1::EPD1::EnableTTBR1Walks
                    + TCR_EL1::EPD0::DisableTTBR0Walks
                    + TCR_EL1::A1::TTBR1,
            );

            barrier::isb(barrier::SY);
        }
    }
}
