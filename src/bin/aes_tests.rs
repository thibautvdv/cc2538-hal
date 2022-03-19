#![no_main]
#![no_std]
#![feature(default_alloc_error_handler)]
#![feature(bench_black_box)]

use cortex_m::asm;
use cortex_m_rt as rt;
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

    let mut aes_crypto = Crypto::new(&mut periph.AES, &mut periph.PKA)
        .aes_engine()
        .ccm_mode();

    //let mut store = AesKeyStore::default();

    let key = crate::aes_engine::keys::AesKey::Key128([
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ]);

    let aes_keys_128 = crate::aes_engine::keys::AesKeys::create(
        &[key],
        crate::aes_engine::keys::AesKeySize::Key128,
        0,
    );
    aes_crypto.load_key(&aes_keys_128);

    //let index = aes_crypto.load_key(&mut store, &key[..]);
    let adata: [u8; 0] = [];
    let mut mdata = [
        0x14, 0xaa, 0xbb, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
        0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    ];

    let nonce = [
        0x00, 0x00, 0xf0, 0xe0, 0xd0, 0xc0, 0xb0, 0xa0, 0x00, 0x00, 0x00, 0x00, 0x05,
    ];

    let mut data_out = [0; 20];

    aes_crypto.ccm_encrypt(
        0,
        2,
        &nonce[..],
        0,
        &adata[..],
        &mdata[..],
        &mut data_out[..],
    );

    rprintln!("{:0x?}", data_out);

    aes_crypto.ccm_decrypt(
        0,
        2,
        &nonce[..],
        0,
        &adata[..],
        &data_out[..],
        &mut mdata[..],
    );

    rprintln!("{:0x?}", mdata);

    loop {
        asm::nop();
    }
}
