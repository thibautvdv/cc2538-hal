#![no_main]
#![no_std]
#![feature(default_alloc_error_handler)]
#![feature(bench_black_box)]

use core::hint::black_box;

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

use cc2538_hal::{crypto::*, gpio::*, ioc::*, serial::*, sys_ctrl::*};
use cc2538_pac as pac;

use core::fmt::Write;

#[entry]
fn main() -> ! {
    rtt_init_print!(BlockIfFull);

    // Setup the allocator
    // let start = cortex_m_rt::heap_start() as usize;
    // let size = 4048;
    // unsafe { ALLOCATOR.init(start, size) };

    match inner_main() {
        Ok(()) => cortex_m::peripheral::SCB::sys_reset(),
        Err(e) => panic!("{}", e),
    }
}

fn inner_main() -> Result<(), &'static str> {
    let periph = pac::Peripherals::take().ok_or("unable to get peripherals")?;

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
    sys_ctrl.enable_uart0_in_active_mode();

    sys_ctrl.reset_aes();
    let mut sys_ctrl = sys_ctrl.freeze();
    sys_ctrl.clear_reset_aes();

    let clocks = sys_ctrl.config();

    let uart0 = periph.UART0;
    let mut ioc = periph.IOC.split();
    let mut gpioa = periph.GPIO_A.split();

    let rx_pin = gpioa.pa0.downgrade().as_uart0_rxd(&mut ioc.uartrxd_uart0);
    let tx_pin = gpioa
        .pa1
        .into_alt_output_function(
            &mut gpioa.dir,
            &mut gpioa.afsel,
            &mut ioc.pa1_sel,
            &mut ioc.pa1_over,
            OutputFunction::Uart0Txd,
        )
        .downgrade();

    let serial = Serial::uart0(uart0, (tx_pin, rx_pin), 115200u32, clocks);
    let (mut tx, _) = serial.split();

    let crypto = periph.AES.constrain();
    let mut sha256 = crypto.sha256_engine();

    let data: [(&[u8], &[u8]); 7] = [
        (
            b"abc",
            &[
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
                0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
                0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
                0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
            ],
        ),
        (
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            &[
                0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8,
                0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
                0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67,
                0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1,
            ],
        ),
        (
            b"abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmn",
            &[
                0x15, 0xd2, 0x3e, 0xea, 0x57, 0xb3, 0xd4, 0x61,
                0xbf, 0x38, 0x91, 0x12, 0xab, 0x4c, 0x43, 0xce,
                0x85, 0xe1, 0x68, 0x23, 0x8a, 0xaa, 0x54, 0x8e,
                0xc8, 0x6f, 0x0c, 0x9d, 0x65, 0xf9, 0xb9, 0x23,
            ],
        ),
        (
            b"abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl",
            &[
                0xf8, 0xa3, 0xf2, 0x26, 0xfc, 0x42, 0x10, 0xe9,
                0x0d, 0x13, 0x0c, 0x7f, 0x41, 0xf2, 0xbe, 0x66,
                0x45, 0x53, 0x85, 0xd2, 0x92, 0x0a, 0xda, 0x78,
                0x15, 0xf8, 0xf7, 0x95, 0xd9, 0x44, 0x90, 0x5f,
            ],
        ),
        (
            b"abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl",
            &[
                0x2f, 0xcd, 0x5a, 0x0d, 0x60, 0xe4, 0xc9, 0x41,
                0x38, 0x1f, 0xcc, 0x4e, 0x00, 0xa4, 0xbf, 0x8b,
                0xe4, 0x22, 0xc3, 0xdd, 0xfa, 0xfb, 0x93, 0xc8,
                0x09, 0xe8, 0xd1, 0xe2, 0xbf, 0xff, 0xae, 0x8e,
            ],
        ),
        (
            b"abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmn",
            &[
                0x92, 0x90, 0x1c, 0x85, 0x82, 0xe3, 0x1c, 0x05,
                0x69, 0xb5, 0x36, 0x26, 0x9c, 0xe2, 0x2c, 0xc8,
                0x30, 0x8b, 0xa4, 0x17, 0xab, 0x36, 0xc1, 0xbb,
                0xaf, 0x08, 0x4f, 0xf5, 0x8b, 0x18, 0xdc, 0x6a,
            ],
        ),
        (
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            &[
                0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8,
                0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
                0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67,
                0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1,
            ],
        ),
    ];

    let mut digest = [0; 32];

    for (input, output) in data.iter() {
        black_box(&mut digest);
        black_box(&core_periph);
        let start = DWT::cycle_count();
        sha256.sha256(input, &mut digest);
        let end = DWT::cycle_count();
        black_box(&core_periph);
        black_box(&mut digest);
        //rprintln!(
            //"Result: {:2x?} in {} cycles",
            //digest,
            //end.wrapping_sub(start)
        //);
        tx.write_fmt(format_args!(
            "Result: {:2x?} in {} cycles",
            digest,
            end.wrapping_sub(start)
        )).unwrap();
        assert_eq!(digest, *output);
    }

    //rprintln!("Done!");
    //rprintln!("Tests seems correct!");
    tx.write_str("Done!").unwrap();
    tx.write_str("Tests seems correct!").unwrap();

    loop {
        asm::nop();
    }
}
