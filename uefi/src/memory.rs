use core::mem::size_of;

use cortex_a::asm::barrier;
use cortex_a::registers::*;
use tock_registers::interfaces::Writeable;
use tock_registers::interfaces::ReadWriteable;

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

pub enum TableIndex {
    Level0(u64),
    Level1(u64, u64),
    Level2(u64, u64, u64),
    Level3(u64, u64, u64, u64),
}

impl TableIndex {
    /// only works under recursive paging
    pub fn virt_addr(self) -> u64 {
        let u64sz = size_of::<u64>() as u64;
        match self {
            TableIndex::Level0(slot) => encode_address(NINE_1, NINE_1, NINE_1, NINE_1, slot * u64sz),
            TableIndex::Level1(l0, slot) => encode_address(NINE_1, NINE_1, NINE_1, l0, slot * u64sz),
            TableIndex::Level2(l0, l1, slot) => encode_address(NINE_1, NINE_1, l0, l1, slot * u64sz),
            TableIndex::Level3(l0, l1, l2, slot) => encode_address(NINE_1, l0, l1, l2, slot * u64sz),
        }
    }
}

const VALID_ENTRY_FLAG: u64 = 1 <<  0;
const NOT_A_BLOCK_FLAG: u64 = 1 <<  1;
const    ACCESSED_FLAG: u64 = 1 << 10;

fn table_descriptor(addr: u64) -> u64 {
    assert_eq!(addr & !PAGE_ADDRESS_MASK, 0);

    addr | VALID_ENTRY_FLAG | NOT_A_BLOCK_FLAG | ACCESSED_FLAG
}

// makes writeable, executable page entries
fn page_descriptor(addr: u64) -> u64 {
    assert_eq!(addr & !PAGE_ADDRESS_MASK, 0);

    addr | VALID_ENTRY_FLAG | NOT_A_BLOCK_FLAG | ACCESSED_FLAG
}

fn slot_available(slot: u64) -> bool {
    (slot & VALID_ENTRY_FLAG) == 0
}

fn disable_mmu() {
    SCTLR_EL1.modify(SCTLR_EL1::M::Disable);
    unsafe { barrier::isb(barrier::SY) };
}

fn enable_mmu() {
    SCTLR_EL1.modify(SCTLR_EL1::M::Enable);
    unsafe { barrier::isb(barrier::SY) };
}

// the logger used by this function
// is set up by UEFI and is no longer
// usable once boot services have been
// exited
fn _debug_table(addr: *mut u64, level: usize) {
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
                    _debug_table(next, level + 1);
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
    next_free_page_pa: u64,

    active: bool,
}

impl Aarch64MemoryManager {
    /// An object which manages a memory map
    ///
    /// Note: Identity mapping must be active
    /// or mmu must be disabled when you call
    /// this constructor
    pub fn new(free: &[(u64, u64)]) -> Self {
        let mut next = 0;
        for (mut address, size) in free.iter() {
            for _ in 0..*size {
                let page_beginning = address as *mut u64;
                unsafe { *page_beginning = next };
                next = address;
                address += PAGE_SIZE as u64;
            }
        }

        let mut this = Self {
            l0_table: 0usize as *mut u64,
            next_free_page_pa: next,
            active: false,
        };

        let emergency_l3 = this.get_free_page(true) as *mut u64;
        let emergency_l2 = this.get_free_page(true) as *mut u64;
        let emergency_l1 = this.get_free_page(true) as *mut u64;

        this.l0_table = this.get_free_page(true) as *mut u64;
        unsafe {
            *emergency_l2 = table_descriptor(emergency_l3 as u64);
            *emergency_l1 = table_descriptor(emergency_l2 as u64);
            *this.l0_table = table_descriptor(emergency_l1 as u64);

            // recursive paging
            let last_entry = this.l0_table.add(511).as_mut().unwrap();
            *last_entry = table_descriptor(this.l0_table as u64);
        }

        this
    }

    pub fn disable_mmu(&mut self) {
        disable_mmu();
        self.active = false;
    }

    pub fn enable_mmu(&mut self) {
        enable_mmu();
        self.active = true;
    }

    // can only be used after recursive paging and
    // emergency mapping have been setup (in constructor)
    fn emergency_map(&mut self, phys_addr: Option<u64>) -> *mut u64 {
        let emergency_l3_spot = TableIndex::Level3(0, 0, 0, 1).virt_addr() as *mut u64;

        let descriptor = match phys_addr {
            Some(phys_addr) => page_descriptor(phys_addr),
            None => 0,
        };

        unsafe { *emergency_l3_spot = descriptor };
        encode_address(0, 0, 0, 1, 0) as *mut u64
    }

    /// Selects a page from unused memory
    /// and marks it as used
    pub fn get_free_page(&mut self, zero: bool) -> u64 {
        let address = self.next_free_page_pa;
        assert_ne!(address, 0);

        let page_beginning = if self.active {
            self.emergency_map(Some(address))
        } else {
            address as *mut u64
        };

        unsafe {
            self.next_free_page_pa = *page_beginning;

            if zero {
                page_beginning.write_bytes(0, TABLE_SIZE);
            }
        }

        if self.active {
            self.emergency_map(None);
        }

        address
    }

    /// Removes a page from the memory map
    /// and (optionally) mark it as available
    /// for future mappings
    pub fn unmap_page(&mut self, virt_addr: u64, mark_free: bool) {
        if mark_free {
            let accessible = virt_addr as *mut u64;
            unsafe { *accessible = self.next_free_page_pa };
        }

        let (l0, l1, l2, l3, offset) = decode_address(virt_addr);
        assert_eq!(offset, 0);

        let l3_slot_va = TableIndex::Level3(l0, l1, l2, l3).virt_addr() as *mut u64;
        let l3_slot_ref = unsafe { l3_slot_va.as_mut().unwrap() };
        assert!(!slot_available(*l3_slot_ref));

        if mark_free {
            let page_pa = *l3_slot_ref & PAGE_ADDRESS_MASK;
            self.next_free_page_pa = page_pa;
        }

        *l3_slot_ref = 0;
    }

    /// Maps a range of pages, starting at specified addresses
    pub fn map(&mut self, mut virt_addr: u64, mut phys_addr: u64, pages: usize) {
        for _ in 0..pages {
            let (l0, l1, l2, l3, offset) = decode_address(virt_addr);
            assert_eq!(offset, 0);
            // 0x1000 is the address for emergency mapping
            assert_ne!(virt_addr, 0x1000);

            if self.active {

                let l0_slot_va = TableIndex::Level0(l0).virt_addr() as *mut u64;
                if slot_available(unsafe { *l0_slot_va }) {
                    let l1_table_pa = self.get_free_page(true);
                    unsafe { *l0_slot_va = table_descriptor(l1_table_pa) };
                }

                let l1_slot_va = TableIndex::Level1(l0, l1).virt_addr() as *mut u64;
                if slot_available(unsafe { *l1_slot_va }) {
                    let l2_table_pa = self.get_free_page(true);
                    unsafe { *l1_slot_va = table_descriptor(l2_table_pa) };
                }

                let l2_slot_va = TableIndex::Level2(l0, l1, l2).virt_addr() as *mut u64;
                if slot_available(unsafe { *l2_slot_va }) {
                    let l3_table_pa = self.get_free_page(true);
                    unsafe { *l2_slot_va = table_descriptor(l3_table_pa) };
                }

                let l3_slot_va = TableIndex::Level3(l0, l1, l2, l3).virt_addr() as *mut u64;
                let l3_slot_ref = unsafe { l3_slot_va.as_mut().unwrap() };
                assert!(slot_available(*l3_slot_ref));
                *l3_slot_ref = page_descriptor(phys_addr);

            } else {
                // assume we're under identity mapping
                let mut ptr = self.l0_table;
                unsafe {
                    for index in [l0, l1, l2] {
                        let slot = ptr.add(index as usize).as_mut().unwrap();
                        if slot_available(*slot) {
                            let table = self.get_free_page(true);
                            *slot = table_descriptor(table);
                        }
                        ptr = (*slot & PAGE_ADDRESS_MASK) as *mut u64;
                    }

                    let slot = ptr.add(l3 as usize).as_mut().unwrap();
                    assert!(slot_available(*slot));
                    *slot = page_descriptor(phys_addr);
                }
            }

            virt_addr += PAGE_SIZE as u64;
            phys_addr += PAGE_SIZE as u64;
        }
    }

    /// Sets up various AARCH64 registers so that
    /// this mapping will work as expected once you
    /// enable the MMU
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
