#![no_main]
#![no_std]
#![feature(default_alloc_error_handler)]
#![feature(bench_black_box)]

use cortex_m::asm;
use cortex_m_rt as rt;
use pac::DWT;
use rt::entry;

use panic_rtt_target as _;

extern crate alloc;
use alloc_cortex_m::CortexMHeap;

#[global_allocator]
static ALLOCATOR: CortexMHeap = CortexMHeap::empty();

use rtt_target::{rprintln, rtt_init_print};

use cc2538_hal::{crypto::*, sys_ctrl::*};
use cc2538_pac as pac;

#[entry]
fn main() -> ! {
    rtt_init_print!(BlockIfFull);

    match inner_main() {
        Ok(()) => cortex_m::peripheral::SCB::sys_reset(),
        Err(e) => panic!("{}", e),
    }
}

fn inner_main() -> Result<(), &'static str> {
    let mut periph = pac::Peripherals::take().ok_or("unable to get peripherals")?;

    let mut core_periph = cortex_m::Peripherals::take().unwrap();
    core_periph.DCB.enable_trace();
    core_periph.DWT.enable_cycle_counter();

    // Setup the clock
    let mut sys_ctrl = periph.SYS_CTRL.constrain();
    sys_ctrl.set_sys_div(ClockDiv::Clock32Mhz);
    sys_ctrl.set_io_div(ClockDiv::Clock32Mhz);
    sys_ctrl.enable_radio_in_active_mode();
    sys_ctrl.enable_gpt0_in_active_mode();
    sys_ctrl.enable_aes_in_active_mode();
    sys_ctrl.enable_pka_in_active_mode();

    let mut sys_ctrl = sys_ctrl.freeze();

    sys_ctrl.reset_aes();
    sys_ctrl.clear_reset_aes();

    sys_ctrl.reset_pka();
    sys_ctrl.clear_reset_pka();

    let mut ecc_crypto = Crypto::new(&mut periph.AES, &mut periph.PKA).ecc_engine();

    let curve = EccCurveInfo::<8>::nist_p_192();
    let scalar = [0; 6];
    let point = EcPoint {
        x: &curve.x_coef[..],

        y: &curve.y_coef[..],
    };

    let mut result = [0u32; 16];
    rprintln!("Start mul at {}!", DWT::cycle_count());
    ecc_crypto.mul(&curve, &scalar[..], &point, &mut result[..]);

    while ecc_crypto.is_pka_in_use() {}

    rprintln!("Result: {:x?}", result);
    rprintln!("Done at {}!", DWT::cycle_count());

    loop {
        asm::nop();
    }
}
