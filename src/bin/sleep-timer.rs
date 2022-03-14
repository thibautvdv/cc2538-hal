#![no_main]
#![no_std]
#![feature(default_alloc_error_handler)]

//use mutiny_rs::task;
//use mutiny_async::task;

use cortex_m::asm;
use cortex_m_rt as rt;
use rt::entry;

use panic_rtt_target as _;

extern crate alloc;
use alloc_cortex_m::CortexMHeap;

#[global_allocator]
static ALLOCATOR: CortexMHeap = CortexMHeap::empty();

use rtt_target::rtt_init_print;

use cc2538_hal::sys_ctrl::*;
use cc2538_pac as pac;

#[entry]
fn main() -> ! {
    rtt_init_print!();

    // Setup the allocator
    let start = cortex_m_rt::heap_start() as usize;
    let size = 4048;
    unsafe { ALLOCATOR.init(start, size) };

    match inner_main() {
        Ok(()) => cortex_m::peripheral::SCB::sys_reset(),
        Err(e) => panic!("{}", e),
    }
}

fn inner_main() -> Result<(), &'static str> {
    let mut _core_periph = cortex_m::Peripherals::take().ok_or("unable to get core peripherals")?;
    let periph = pac::Peripherals::take().ok_or("unable to get peripherals")?;

    // Setup the clock
    let mut sys_ctrl = periph.SYS_CTRL.constrain();
    sys_ctrl.set_sys_div(ClockDiv::Clock16Mhz);
    sys_ctrl.set_io_div(ClockDiv::Clock16Mhz);
    sys_ctrl.enable_uart0_in_active_mode();
    let _clocks = sys_ctrl.freeze();
    //let clock_config = clocks.config();

    unsafe {
        cortex_m::interrupt::enable();
    }

    //let mut sleep_timer = periph.SMWDTHROSC.split();

    //let mut sec = 0;
    loop {
        //sleep_timer
        //.wait(Duration::from_secs(1), &clock_config)
        //.await;
        //rprintln!("{} sec", sec);
        //sec += 1;
        asm::nop();
    }
}
