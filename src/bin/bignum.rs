#![no_main]
#![no_std]
#![feature(bench_black_box)]

use cortex_m::asm;
use cortex_m_rt as rt;
use rt::entry;

use panic_rtt_target as _;

use rtt_target::{rprintln, rtt_init_print};

use cc2538_hal::{
    crypto::{bignum::BigNum, *},
    sys_ctrl::*,
};
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

    let _crypto = Crypto::new(&mut periph.AES, &mut periph.PKA);

    let mut num1 = [0u32; 4];
    num1[0] = 4;
    let num2 = [0xffu32; 4];
    let mut result = [0u32; 16];

    rprintln!("Operations with the BigNum struct:");
    let mut bignum1 = BigNum::<16>::new(1);
    bignum1.inner_mut()[0] = 4;
    let mut bignum2 = BigNum::<16>::new(5);
    bignum2.inner_mut()[..4].copy_from_slice(&[0xff; 4]);
    let mut bignum3 = BigNum::<16>::new(5);
    bignum3.inner_mut()[0] = 42;

    let bignum_result = bignum1.add(&bignum2).unwrap();
    rprintln!("{} + {} = {}", bignum1, bignum2, bignum_result);

    let bignum_result = bignum2.sub(&bignum1).unwrap();
    rprintln!("{} - {} = {}", bignum2, bignum1, bignum_result);

    let bignum_result = bignum2.add_sub(&bignum3, &bignum1).unwrap();
    rprintln!(
        "{} + {} - {} = {}",
        bignum2,
        bignum3,
        bignum1,
        bignum_result
    );

    let bignum_result = bignum1.mul(&bignum2).unwrap();
    rprintln!("{} * {} = {}", bignum1, bignum2, bignum_result);

    //let (bignum_result, ) = bignum1.div(&bignum2).unwrap();
    //rprintln!("{} / {} = {} (remainder {})", bignum1, bignum2, bignum_result, bignum_result);

    let bignum_result = bignum2.modulo(&bignum1).unwrap();
    rprintln!("{} mod {} = {}", bignum2, bignum1, bignum_result);

    let bignum_result = bignum2.inv_mod(&bignum1);
    rprintln!("{}^-1 mod {} = {:?}", bignum2, bignum1, bignum_result);

    let mut base = BigNum::<16>::new(4);
    base.inner_mut().copy_from_slice(&[0x0fu32; 4]);
    let bignum_result = bignum1.exp(&bignum2, &base);
    rprintln!("{}^{} mod {} = {}", base, bignum1, bignum2, bignum_result);

    rprintln!(
        "{} {} {}",
        bignum1,
        match bignum1.compare(&bignum2).unwrap() {
            core::cmp::Ordering::Less => "<",
            core::cmp::Ordering::Equal => "=",
            core::cmp::Ordering::Greater => ">",
        },
        bignum2
    );

    rprintln!("");
    rprintln!("Operations with raw slices:");

    let len = Crypto::add(&num1, &num2, &mut result).unwrap();
    rprintln!("Addition: {:0x?}", &result[..len]);

    let len = Crypto::sub(&num2, &num1, &mut result).unwrap();
    rprintln!("Subtract: {:0x?}", &result[..len]);

    let len = Crypto::mul(&num1, &num2, &mut result).unwrap();
    rprintln!("Multiplication: {:0x?}", &result[..len]);

    //crypto.div(&mut num1, &mut num2, &mut result);
    //rprintln!("Division: {:0x?}", result);

    Crypto::modulo(&num1, &num2, &mut result);
    rprintln!("Modulo: {:0x?}", result);

    let len = Crypto::inv_modulo(&num1, &num2, &mut result);
    rprintln!("Inverse modulo: {:0x?}", result);

    let base = [0x0fu32; 4];
    let len = Crypto::exp(&num1, &num2, &base, &mut result);
    rprintln!("Exponentiate: {:0x?}", result);

    loop {
        asm::bkpt();
    }
}
