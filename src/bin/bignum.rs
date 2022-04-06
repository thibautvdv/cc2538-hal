#![no_main]
#![no_std]
#![feature(bench_black_box)]

use cortex_m::asm;
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

    let mut crypto = Crypto::new(&mut periph.AES, &mut periph.PKA);

    let mut num1 = [0u32; 4];
    num1[0] = 4;
    let num2 = [0xffu32; 4];
    //num2[0] = 2;
    let mut result = [0u32; 16];

    crypto.add(&num1, &num2, &mut result);
    rprintln!("Addition: {:0x?}", result);

    crypto.sub(&num1, &num2, &mut result);
    rprintln!("Subtract: {:0x?}", result);

    crypto.mul(&num1, &num2, &mut result);
    rprintln!("Multiplication: {:0x?}", result);

    //crypto.div(&mut num1, &mut num2, &mut result);
    //rprintln!("Division: {:0x?}", result);

    crypto.modulo(&num1, &num2, &mut result);
    rprintln!("Modulo: {:0x?}", result);

    crypto.inv_modulo(&num1, &num2, &mut result);
    rprintln!("Inverse modulo: {:0x?}", result);

    let base = [0x0fu32; 4];
    //base[0] = 2;
    crypto.exp(&num1, &num2, &base, &mut result);
    rprintln!("Exponentiate: {:0x?}", result);

    loop {
        asm::nop();
    }
}
