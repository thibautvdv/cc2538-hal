#![no_main]
#![no_std]

use cortex_m::asm;
use cortex_m::peripheral::DWT;
use cortex_m_rt as rt;
use rt::entry;

use panic_rtt_target as _;

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
    let mut periph = unsafe { pac::Peripherals::steal() };

    let mut core_periph = cortex_m::Peripherals::take().unwrap();
    core_periph.DCB.enable_trace();
    core_periph.DWT.enable_cycle_counter();

    // Setup the clock
    let mut sys_ctrl = periph.sys_ctrl.constrain();
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

    let mut ecc_crypto = Crypto::new(&mut periph.aes, &mut periph.pka);

    let curve = crate::ecc::EccCurveInfo::nist_p_256();
    let pointa = crate::ecc::EcPoint {
        x: curve.bp_x,

        y: curve.bp_y,
    };

    let pointb = crate::ecc::EcPoint {
        x: curve.bp_x,

        y: curve.bp_y,
    };

    let mut result = [0u32; 16];

    let start = DWT::cycle_count();
    ecc_crypto
        .ecc_add(&curve, &pointa, &pointb, &mut result[..])
        .unwrap();
    let end = DWT::cycle_count();
    rprintln!("Result addition: {:x?} in {} cycles", result, end - start);

    let curve = crate::ecc::EccCurveInfo::nist_p_256();
    let mut scalar = [0; 8];
    scalar[0] = 6;
    let pointa = crate::ecc::EcPoint {
        x: curve.bp_x,

        y: curve.bp_y,
    };

    let mut result = [0u32; 16];

    let start = DWT::cycle_count();
    ecc_crypto
        .ecc_mul(&curve, &scalar, &pointa, &mut result[..])
        .unwrap();
    let end = DWT::cycle_count();
    rprintln!(
        "Result multiplication: {:x?} in {} cycles",
        result,
        end - start
    );

    loop {
        asm::nop();
    }
}
