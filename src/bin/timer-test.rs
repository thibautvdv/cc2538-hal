#![no_main]
#![no_std]

use cortex_m_rt as rt;
use rt::entry;

use panic_rtt_target as _;

use rtt_target::rtt_init_print;

use cc2538_hal::sys_ctrl::*; // , timers::*};
use cc2538_pac as pac;

#[entry]
fn main() -> ! {
    rtt_init_print!();

    match inner_main() {
        Ok(()) => cortex_m::peripheral::SCB::sys_reset(),
        Err(e) => panic!("{}", e),
    }
}

fn inner_main() -> Result<(), &'static str> {
    let mut _core_periph = cortex_m::Peripherals::take().ok_or("unable to get core peripherals")?;
    let periph = unsafe { pac::Peripherals::steal() };

    // Setup the clock
    let mut sys_ctrl = periph.SYS_CTRL.constrain();
    sys_ctrl.set_sys_div(ClockDiv::Clock16Mhz);
    sys_ctrl.set_io_div(ClockDiv::Clock16Mhz);
    sys_ctrl.enable_gpt0_in_active_mode();
    sys_ctrl.enable_gpt0_in_sleep_mode();
    sys_ctrl.enable_gpt0_in_deep_sleep_mode();
    //let clocks = sys_ctrl.freeze();
    //let clock_config = clocks.config();

    unsafe {
        cortex_m::interrupt::enable();
    }

    //let timer0 = periph.GPTIMER0.split();
    //let (mut timer0, timer0a, timer0b) = timer0.split();

    //let mut timer0a = timer0a.into_one_shot_timer(&mut timer0);
    //let mut timer0b = timer0b.into_one_shot_timer(&mut timer0);

    //task::spawn(async move {
    //loop {
    //timer0a = timer0a
    //.wait(Duration::from_millis(250), &clock_config)
    //.await;
    //rprintln!("timera");
    //}
    //});

    //task::block_on(async move {
    //loop {
    //timer0b = timer0b.wait(Duration::from_secs(1), &clock_config).await;
    //rprintln!("timerb");
    //}
    //})
    loop {
        cortex_m::asm::nop();
    }
}
