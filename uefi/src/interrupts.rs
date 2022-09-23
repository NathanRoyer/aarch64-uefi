use core::arch::global_asm;
use core::arch::asm;
use core::cell::UnsafeCell;
use core::fmt;

use cortex_a::asm::barrier;
use cortex_a::registers::*;

use tock_registers::interfaces::Writeable;
use tock_registers::interfaces::Readable;
use tock_registers::registers::InMemoryRegister;

global_asm!(include_str!("interrupts.s"));

/// Wrapper structs for memory copies of registers.
#[repr(transparent)]
struct SpsrEL1(InMemoryRegister<u64, SPSR_EL1::Register>);
struct EsrEL1(InMemoryRegister<u64, ESR_EL1::Register>);

pub static mut LAST_EXC: Option<ExceptionContext> = None;

/// The exception context as it is stored on the stack on exception entry.
#[repr(C)]
pub struct ExceptionContext {
    /// General Purpose Registers.
    gpr: [u64; 30],

    /// The link register, aka x30.
    lr: u64,

    /// Exception link register. The program counter at the time the exception happened.
    elr_el1: u64,

    /// Saved program status.
    spsr_el1: SpsrEL1,

    /// Exception syndrome register.
    esr_el1: EsrEL1,
}

fn default_exception_handler(exc: &ExceptionContext, origin: &'static str) {
    log::info!("exception: {}", origin);
    unsafe { LAST_EXC = Some(ExceptionContext {
        gpr: exc.gpr,
        lr: exc.lr,
        elr_el1: exc.elr_el1,
        spsr_el1: SpsrEL1(InMemoryRegister::new(exc.spsr_el1.0.get())),
        esr_el1: EsrEL1(InMemoryRegister::new(exc.esr_el1.0.get())),
    }) };
}

#[no_mangle]
extern "C" fn current_el0_synchronous(_e: &mut ExceptionContext) {
    panic!("Should not be here. Use of SP_EL0 in EL1 is not supported.")
}

#[no_mangle]
extern "C" fn current_el0_irq(_e: &mut ExceptionContext) {
    panic!("Should not be here. Use of SP_EL0 in EL1 is not supported.")
}

#[no_mangle]
extern "C" fn current_el0_serror(_e: &mut ExceptionContext) {
    panic!("Should not be here. Use of SP_EL0 in EL1 is not supported.")
}

#[no_mangle]
extern "C" fn current_elx_synchronous(e: &mut ExceptionContext) {
    default_exception_handler(e, "current_elx_synchronous");
    // e.elr_el1 += 4;
}

#[no_mangle]
extern "C" fn current_elx_irq(e: &mut ExceptionContext) {
    default_exception_handler(e, "current_elx_irq");
}

#[no_mangle]
extern "C" fn current_elx_serror(e: &mut ExceptionContext) {
    default_exception_handler(e, "current_elx_serror");
}

#[no_mangle]
extern "C" fn lower_aarch64_synchronous(e: &mut ExceptionContext) {
    default_exception_handler(e, "lower_aarch64_synchronous");
}

#[no_mangle]
extern "C" fn lower_aarch64_irq(e: &mut ExceptionContext) {
    default_exception_handler(e, "lower_aarch64_irq");
}

#[no_mangle]
extern "C" fn lower_aarch64_serror(e: &mut ExceptionContext) {
    default_exception_handler(e, "lower_aarch64_serror");
}

#[no_mangle]
extern "C" fn lower_aarch32_synchronous(e: &mut ExceptionContext) {
    default_exception_handler(e, "lower_aarch32_synchronous");
}

#[no_mangle]
extern "C" fn lower_aarch32_irq(e: &mut ExceptionContext) {
    default_exception_handler(e, "lower_aarch32_irq");
}

#[no_mangle]
extern "C" fn lower_aarch32_serror(e: &mut ExceptionContext) {
    default_exception_handler(e, "lower_aarch32_serror");
}

impl EsrEL1 {
    #[inline(always)]
    fn exception_class(&self) -> Option<ESR_EL1::EC::Value> {
        self.0.read_as_enum(ESR_EL1::EC)
    }
}

impl ExceptionContext {
    #[inline(always)]
    fn exception_class(&self) -> Option<ESR_EL1::EC::Value> {
        self.esr_el1.exception_class()
    }

    #[inline(always)]
    fn fault_address_valid(&self) -> bool {
        use ESR_EL1::EC::Value::*;

        match self.exception_class() {
            None => false,
            Some(ec) => matches!(
                ec,
                InstrAbortLowerEL
                    | InstrAbortCurrentEL
                    | PCAlignmentFault
                    | DataAbortLowerEL
                    | DataAbortCurrentEL
                    | WatchpointLowerEL
                    | WatchpointCurrentEL
            ),
        }
    }
}

pub fn setup() {
    unsafe {
        extern "Rust" {
            // in assembly file
            static __exception_vector_start: UnsafeCell<()>;
        }

        VBAR_EL1.set(__exception_vector_start.get() as u64);

        barrier::isb(barrier::SY);

        log::info!("DAIF before: {:?}", DAIF.get());

        DAIF.write(
            DAIF::D::Masked
            + DAIF::A::Masked
            + DAIF::I::Masked
            + DAIF::F::Masked,
        );

        log::info!("DAIF after: {:?}", DAIF.get());

        barrier::isb(barrier::SY);
    }
}

#[rustfmt::skip]
impl fmt::Display for SpsrEL1 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Raw value.
        writeln!(f, "\rSPSR_EL1: {:#010x}", self.0.get())?;

        let to_flag_str = |x| -> _ { if x { "Set" } else { "Not set" } };

        writeln!(f, "\r      Flags:")?;
        writeln!(f, "\r            Negative (N): {}", to_flag_str(self.0.is_set(SPSR_EL1::N)))?;
        writeln!(f, "\r            Zero     (Z): {}", to_flag_str(self.0.is_set(SPSR_EL1::Z)))?;
        writeln!(f, "\r            Carry    (C): {}", to_flag_str(self.0.is_set(SPSR_EL1::C)))?;
        writeln!(f, "\r            Overflow (V): {}", to_flag_str(self.0.is_set(SPSR_EL1::V)))?;

        let to_mask_str = |x| -> _ { if x { "Masked" } else { "Unmasked" } };

        writeln!(f, "\r      Exception handling state:")?;
        writeln!(f, "\r            Debug  (D): {}", to_mask_str(self.0.is_set(SPSR_EL1::D)))?;
        writeln!(f, "\r            SError (A): {}", to_mask_str(self.0.is_set(SPSR_EL1::A)))?;
        writeln!(f, "\r            IRQ    (I): {}", to_mask_str(self.0.is_set(SPSR_EL1::I)))?;
        writeln!(f, "\r            FIQ    (F): {}", to_mask_str(self.0.is_set(SPSR_EL1::F)))?;

        write!(f, "\r      Illegal Execution State (IL): {}",
            to_flag_str(self.0.is_set(SPSR_EL1::IL))
        )
    }
}

#[rustfmt::skip]
impl fmt::Display for EsrEL1 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Raw print of whole register.
        writeln!(f, "\rESR_EL1: {:#010x}", self.0.get())?;

        // Raw print of exception class.
        write!(f, "\r      Exception Class         (EC) : {:#x}", self.0.read(ESR_EL1::EC))?;

        // Exception class.
        let ec_translation = match self.exception_class() {
            Some(ESR_EL1::EC::Value::DataAbortCurrentEL) => "Data Abort, current EL",
            _ => "N/A",
        };
        writeln!(f, "\r - {}", ec_translation)?;

        // Raw print of instruction specific syndrome.
        write!(f, "\r      Instr Specific Syndrome (ISS): {:#x}", self.0.read(ESR_EL1::ISS))
    }
}

impl fmt::Display for ExceptionContext {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "\r{}", self.esr_el1)?;

        if self.fault_address_valid() {
            writeln!(f, "\rFAR_EL1: {:#018x}", FAR_EL1.get() as usize)?;
        }

        writeln!(f, "\r{}", self.spsr_el1)?;
        writeln!(f, "\rELR_EL1: {:#018x}", self.elr_el1)?;
        writeln!(f)?;
        writeln!(f, "\rGeneral purpose register:")?;

        #[rustfmt::skip]
        let alternating = |x| -> _ {
            if x % 2 == 0 { "   " } else { "\n" }
        };

        // Print two registers per line.
        for (i, reg) in self.gpr.iter().enumerate() {
            write!(f, "\r      x{: <2}: {: >#018x}{}", i, reg, alternating(i))?;
        }
        write!(f, "\r      lr : {:#018x}", self.lr)
    }
}
