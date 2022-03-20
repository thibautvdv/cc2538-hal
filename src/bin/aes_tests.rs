#![no_main]
#![no_std]
#![feature(default_alloc_error_handler)]
#![feature(bench_black_box)]

use cc2538_hal::crypto::aes_engine::ccm::{AesCcmInfo, self};
use cc2538_hal::crypto::aes_engine::keys::{AesKey, AesKeySize, AesKeys};
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

    let adata: [u8; 0] = [];
    let mut mdata = [
        0x14, 0xaa, 0xbb, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
        0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    ];

    let nonce = [
        0x00, 0x00, 0xf0, 0xe0, 0xd0, 0xc0, 0xb0, 0xa0, 0x00, 0x00, 0x00, 0x00, 0x05,
    ];

    let mut data_out = [0; 20];
    let mut tag = [0; 16];

    let ccm_info = AesCcmInfo::new(0, 2, 0).with_added_auth_data(&adata[..]);

    aes_crypto.encrypt(
        &ccm_info,
        &nonce[..],
        &mdata[..],
        &mut data_out[..],
        &mut tag[..],
    );

    rprintln!("{:0x?}", data_out);

    aes_crypto.decrypt(&ccm_info, &nonce[..], &data_out[..], &mut mdata[..]);
    rprintln!("{:0x?}", mdata);

    sys_ctrl.reset_aes();
    sys_ctrl.clear_reset_aes();

    let key128 = AesKey::Key128([
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f,
        0x3c,
    ]);
    let aes_keys_128 = AesKeys::create(&[key128], AesKeySize::Key128, 0);

    let mut aes = aes_crypto.ctr_mode();
    aes.load_key(&aes_keys_128);

    let nonce = [];
    let ctr = [
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe,
        0xff,
    ];

    let mut output = [0u8; 64];
    let mut decrypted = [0u8; 64];

    let input = [
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17,
        0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf,
        0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a,
        0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b,
        0xe6, 0x6c, 0x37, 0x10,
    ];

    let expected = [
        0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26, 0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d, 0xb6,
        0xce, 0x98, 0x06, 0xf6, 0x6b, 0x79, 0x70, 0xfd, 0xff, 0x86, 0x17, 0x18, 0x7b, 0xb9, 0xff,
        0xfd, 0xff, 0x5a, 0xe4, 0xdf, 0x3e, 0xdb, 0xd5, 0xd3, 0x5e, 0x5b, 0x4f, 0x09, 0x02, 0x0d,
        0xb0, 0x3e, 0xab, 0x1e, 0x03, 0x1d, 0xda, 0x2f, 0xbe, 0x03, 0xd1, 0x79, 0x21, 0x70, 0xa0,
        0xf3, 0x00, 0x9c, 0xee,
    ];

    aes.load_key(&aes_keys_128);
    aes.encrypt(0, &nonce, &ctr, &input, &mut output);

    assert_eq!(output, expected);

    aes.decrypt(
        0,
        &nonce,
        &ctr,
        &output[..input.len()],
        &mut decrypted[..input.len()],
    );
    assert_eq!(input, decrypted);

    loop {
        asm::nop();
    }
}
