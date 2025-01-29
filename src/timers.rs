//! General Purpose Timers

use core::future::Future;
use core::marker::PhantomData;
use core::pin::Pin;
use core::sync::atomic::{self, AtomicBool, Ordering};
use core::task::{Context, Poll, Waker};
use core::time::Duration;

use crate::pac;
use cortex_m::peripheral::NVIC;
use cortex_m_rt::interrupt;
use pac::Interrupt as interrupt;

use paste::paste;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
/// Specifies the mode of operation of a timer.
pub enum Mode {
    OneShot = 0x1,
    Periodic = 0x2,
    Capture = 0x3,
}

#[derive(Copy, Clone)]
/// Count direction of the timer.
pub enum CountDirection {
    Down = 0,
    Up = 1,
}

impl Default for CountDirection {
    fn default() -> Self {
        Self::Down
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum CaptureMode {
    EdgeCount = 0,
    EdgeTime = 1,
}

impl Default for CaptureMode {
    fn default() -> Self {
        Self::EdgeCount
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Event {
    /// Time-out interrupt
    TimeOut,
    /// Capture match interrupt
    CaptureMatch,
    /// Capture event interrupt
    CaptureEvent,
    /// Match interrupt
    Match,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum Config {
    Timer32Bit = 0x0,
    Clock32Bit = 0x1,
    Timer16Bit = 0x4,
}

/// State of the timer where the timer is uninitialised.
pub struct Uninit;
/// State of the timer where the timer is configured.
/// The timer can be enabled and parameters can be changed.
pub struct Configured;

pub struct NotSpecified;
pub struct OneShotTimer;
pub struct PeriodicTimer;
pub struct InputEdgeCountTimer;
pub struct InputEdgeTimeTimer;
pub struct PwmTimer;
pub struct WaitForTriggerTimer;

/// Extension trait used on timers.
pub trait GpTimerExt {
    type Parts;

    fn split(self) -> Self::Parts;
}

macro_rules! timer_registers {
    ([
            $(($TIMERX:ident, $timerx:ident, $name_big:ident, $name_small:ident)),+ $(,)?
    ]) => {
        $(pub struct $name_big;
        impl $name_big {
            pub(crate) fn $name_small(&mut self) -> &$timerx::$name_big {
                unsafe { &(*$TIMERX::ptr()).$name_small() }
            }
        })+
    };
}

macro_rules! timer {
    ([
     $({
         timer: $TIMERX:ident,
         mapped: $timerx:ident,
         name: $type:ident,
         module: $timer_module:ident,
         [
             $(
             $sub_type:ident
             ),+
         ]
     }),+
    ]) => {
        paste! {
        $(
            use cc2538_pac::$TIMERX;
        )+

        $(
            pub mod $timer_module {
                use super::*;
                use cc2538_pac::$timerx;
                use crate::sys_ctrl::ClockConfig;

                pub struct Parts {
                    pub timer: $type,
                    $(
                    pub [<timer $sub_type:lower>]: [<Timer $sub_type>]<Uninit, NotSpecified>,
                    )+
                }

                impl Parts {
                    pub fn split(self) -> ($type, TimerA<Uninit, NotSpecified>, TimerB<Uninit, NotSpecified>) {
                        (self.timer, self.timera, self.timerb)
                    }
                }

                pub struct $type {
                    pub(crate) cfg: Cfg,
                    pub(crate) ctl: Ctl,
                    pub(crate) sync: Sync,
                    pub(crate) imr: Imr,
                    pub(crate) ris: Ris,
                    pub(crate) mis: Mis,
                    pub(crate) icr: Icr,
                    pub(crate) pp: Pp,
                }

                $(
                pub struct [<Timer $sub_type>]<STATE, TYPE> {
                    pub(crate) mr: [<T $sub_type:lower mr>],
                    pub(crate) ilr: [<T $sub_type:lower ilr>],
                    pub(crate) matcher: [<T $sub_type:lower matchr>],
                    pub(crate) pr: [<T $sub_type:lower pr>],
                    pub(crate) pmr: [<T $sub_type:lower pmr>],
                    pub(crate) r: [<T $sub_type:lower r>],
                    pub(crate) v: [<T $sub_type:lower v>],
                    pub(crate) ps: [<T $sub_type:lower ps>],
                    pub(crate) pv: [<T $sub_type:lower pv>],
                    _state: PhantomData<STATE>,
                    _type: PhantomData<TYPE>,
                }

                impl [<Timer $sub_type>]<Uninit, NotSpecified> {
                    /// Disable the timer.
                    pub fn disable(self, timer: &mut $type) -> Self {
                        timer.ctl.ctl().modify(|_, w| w.[<t $sub_type:lower en>]().clear_bit());
                        self
                    }

                    /// Configre the timer as a one shot timer.
                    pub fn into_one_shot_timer(mut self, timer: &mut $type) -> [<Timer $sub_type>]<Uninit, OneShotTimer> {
                        unsafe { timer.cfg.cfg().modify(|_, w| w.gptmcfg().bits(Config::Timer16Bit as u8)) };
                        unsafe { self.mr.[<t $sub_type:lower mr>]().modify(|_, w| w.[<t $sub_type:lower mr>]().bits(Mode::OneShot as u8)) };

                        [<Timer $sub_type>] {
                            mr: self.mr,
                            ilr: self.ilr,
                            matcher: self.matcher,
                            pr: self.pr,
                            pmr: self.pmr,
                            r: self.r,
                            v: self.v,
                            ps: self.ps,
                            pv: self.pv,
                            _state: PhantomData,
                            _type: PhantomData,
                        }
                    }

                    /// Configure the timer as a periodic timer.
                    pub fn into_periodic_timer(mut self, timer: &mut $type) -> [<Timer $sub_type>]<Uninit, PeriodicTimer> {
                        unsafe { timer.cfg.cfg().modify(|_, w| w.gptmcfg().bits(Config::Timer16Bit as u8)) };
                        unsafe { self.mr.[<t $sub_type:lower mr>]().modify(|_, w| w.[<t $sub_type:lower mr>]().bits(Mode::Periodic as u8)) };

                        [<Timer $sub_type>] {
                            mr: self.mr,
                            ilr: self.ilr,
                            matcher: self.matcher,
                            pr: self.pr,
                            pmr: self.pmr,
                            r: self.r,
                            v: self.v,
                            ps: self.ps,
                            pv: self.pv,
                            _state: PhantomData,
                            _type: PhantomData,
                        }
                    }
                }

                impl<TYPE> [<Timer $sub_type>]<Uninit, TYPE> {
                    /// Set the prescaler of the timer.
                    pub fn set_prescaler(&mut self, prescale: u8) {
                        unsafe { self.pr.[<t $sub_type:lower pr>]().modify(|_, w| w.[<t $sub_type:lower psr>]().bits(prescale)) };
                    }

                    /// Mark the timer as configured.
                    /// The timer can now be enabled.
                    pub const fn configure(self) -> [<Timer $sub_type>]<Configured, TYPE> {
                        [<Timer $sub_type>] {
                            mr: self.mr,
                            ilr: self.ilr,
                            matcher: self.matcher,
                            pr: self.pr,
                            pmr: self.pmr,
                            r: self.r,
                            v: self.v,
                            ps: self.ps,
                            pv: self.pv,
                            _state: PhantomData,
                            _type: PhantomData,
                        }
                    }

                    /// Enable wait-on-trigger.
                    pub fn enable_wait_on_trigger(self) -> Self {
                        todo!();
                    }

                    /// Disable wait-on-trigger.
                    pub fn disable_wait_on_trigger(self) -> Self {
                        todo!();
                    }

                    /// Set the count direction of the timer.
                    pub fn set_count_direction(&mut self, dir: CountDirection) {
                        self.mr.[<t $sub_type:lower mr>]().modify(|_, w| match dir {
                            CountDirection::Down => {
                                w.[<t $sub_type:lower cdir>]().clear_bit()
                            },
                            CountDirection::Up => {
                                w.[<t $sub_type:lower cdir>]().set_bit()
                            },
                        });
                    }

                    /// Set the start value of the timer.
                    pub fn set_start_value(&mut self, value: u16){
                        self.ilr.[<t $sub_type:lower ilr>]().modify(|_, w| unsafe {
                            w.bits(value as u32)
                        });
                    }

                    /// Listen to a specific interrupt.
                    pub fn listen(&mut self, event: Event) {
                        let timer = unsafe { &* cc2538_pac::$TIMERX::ptr() };
                        self.mr.[<t $sub_type:lower mr>]().modify(|_, w| w.[<t $sub_type:lower mie>]().set_bit());
                        match event {
                            Event::TimeOut => timer.imr()
                                .modify(|_, w| w.[<t $sub_type:lower toim>]().set_bit()),
                            Event::CaptureMatch => timer.imr()
                                .modify(|_, w| w.[<c $sub_type:lower mim>]().set_bit()),
                            Event::CaptureEvent => timer.imr()
                                .modify(|_, w| w.[<c $sub_type:lower eim>]().set_bit()),
                            Event::Match => timer.imr()
                                .modify(|_, w| w.[<t $sub_type:lower mim>]().set_bit()),
                        };
                    }

                    /// Unlisten to a specific interrupt.
                    pub fn unlisten(self, timer: &mut $type, event: Event) -> Self {
                        match event {
                            Event::TimeOut => timer.imr.imr()
                                .write(|w| w.[<t $sub_type:lower toim>]().clear_bit()),
                            Event::CaptureMatch => timer.imr.imr()
                                .write(|w| w.[<c $sub_type:lower mim>]().clear_bit()),
                            Event::CaptureEvent => timer.imr.imr()
                                .write(|w| w.[<c $sub_type:lower eim>]().clear_bit()),
                            Event::Match => timer.imr.imr()
                                .write(|w| w.[<t $sub_type:lower mim>]().clear_bit()),
                        };

                        self
                    }
                }

                impl [<Timer $sub_type>]<Uninit, PeriodicTimer> {
                    /// Enable snapshot mode.
                    pub fn enable_snapshot_mode(self) -> Self {
                        todo!();
                    }

                    /// Disable snapshot mode.
                    pub fn disable_snapshot_mode(self) -> Self {
                        todo!();
                    }
                }

                impl [<Timer $sub_type>]<Uninit, OneShotTimer> {
                    pub async fn wait<'a>(mut self, dur: Duration, config: &'a ClockConfig) -> Self {
                        struct Wait {
                            timer: Option<[<Timer $sub_type>]<Configured, OneShotTimer>>,
                            installed_waker: bool,
                        }

                        impl Future for Wait {
                            type Output = [<Timer $sub_type>]<Uninit, OneShotTimer>;

                            fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
                                static mut WAKER: Option<Waker> = None;

                                if self.timer.as_ref().unwrap().has_expired() {
                                    if self.installed_waker {
                                        NVIC::mask(pac::Interrupt::[<$TIMERX:upper $sub_type>]);
                                        atomic::compiler_fence(Ordering::Release);
                                        self.timer.as_ref().unwrap().clear_match();
                                        drop(unsafe { WAKER.take() });
                                    }

                                    Poll::Ready(self.timer.take().unwrap().disable())
                                } else {
                                    if !self.installed_waker {
                                        unsafe {
                                            WAKER = Some(cx.waker().clone());
                                            atomic::compiler_fence(Ordering::Release);
                                            NVIC::unmask(pac::Interrupt::[<$TIMERX:upper $sub_type>]);
                                        }

                                        self.installed_waker = true;
                                        self.timer.as_mut().unwrap().enable();

                                        #[interrupt]
                                        #[allow(non_snake_case)]
                                        fn [<$TIMERX:upper $sub_type>]() {
                                            if let Some(waker) = unsafe { WAKER.as_ref() } {
                                                waker.wake_by_ref();
                                                NVIC::mask(pac::Interrupt::[<$TIMERX:upper $sub_type>]);
                                            }
                                        }
                                    } else {
                                        unsafe { NVIC::unmask(pac::Interrupt::[<$TIMERX:upper $sub_type>]) };
                                    }

                                    Poll::Pending
                                }
                            }
                        }

                        // Configure the timer
                        let prescaler = (
                            dur.as_nanos() /
                            (u16::MAX as u128  * (config.io_freq() / 1_000_000) as u128)
                        );
                        let prescaler:u8 = prescaler.min(u8::MAX as u128) as u8;

                        // XXX check if this is correct
                        let start_value = if prescaler != 0 {(
                            dur.as_nanos() * (config.io_freq() / 1_000_000) as u128
                            / prescaler as u128
                            / 1_000
                        )} else {
                            dur.as_nanos() * (config.io_freq() / 1_000_000) as u128
                            / 1_000
                        };

                        let start_value:u16 = if start_value > u16::MAX as u128 {
                            panic!("Timer delay is too big.");
                        } else {
                            start_value as u16
                        };

                        self.set_count_direction(CountDirection::Down);
                        self.set_prescaler(prescaler);
                        self.set_start_value(start_value);
                        self.listen(Event::TimeOut);
                        let timer = self.configure();

                        timer.clear_interrupts();
                        timer.clear_match();

                        Wait {
                            timer: Some(timer),
                            installed_waker: false,
                        }.await
                    }
                }

                impl<TYPE> [<Timer $sub_type>]<Configured, TYPE> {
                    /// Enable the timer.
                    ///
                    /// A timer can only be enabled when it is marked as configured.
                    pub fn enable(&mut self) {
                        let timer = unsafe { &* cc2538_pac::$TIMERX::ptr() };
                        timer.ctl().modify(|_, w| w.[<t $sub_type:lower stall>]().set_bit());
                        timer.ctl().modify(|_, w| w.[<t $sub_type:lower en>]().set_bit());
                    }

                    pub fn disable(self) -> [<Timer $sub_type>]<Uninit, TYPE> {
                        let timer = unsafe { &* cc2538_pac::$TIMERX::ptr() };
                        timer.ctl().modify(|_, w| w.[<t $sub_type:lower en>]().clear_bit());

                        [<Timer $sub_type>] {
                            mr: self.mr,
                            ilr: self.ilr,
                            matcher: self.matcher,
                            pr: self.pr,
                            pmr: self.pmr,
                            r: self.r,
                            v: self.v,
                            ps: self.ps,
                            pv: self.pv,
                            _state: PhantomData,
                            _type: PhantomData,
                        }
                    }

                    /// Check if the timer is enabled.
                    pub fn is_enabled(&mut self, timer: &mut $type) {
                        timer.ctl.ctl().read().[<t $sub_type:lower en>]().bit_is_set();
                    }

                    /// Check if a match has occured.
                    pub fn has_match(&mut self, timer: &mut $type) -> bool {
                        timer.ris.ris().read().[<t $sub_type:lower toris>]().bit_is_set()
                    }

                    /// Check if a match has occured.
                    pub fn has_expired(&self) -> bool {
                        let timer = unsafe { &* cc2538_pac::$TIMERX::ptr() };
                        timer.mis().read().[<t $sub_type:lower tomis>]().bit_is_set()
                    }

                    /// Clear the match.
                    pub fn clear_match(&self) {
                        let timer = unsafe { &* cc2538_pac::$TIMERX::ptr() };
                        timer.icr().modify(|_, w| w.[<t $sub_type:lower tocint>]().set_bit());
                    }

                    pub fn clear_interrupts(&self) {
                        let timer = unsafe { &* cc2538_pac::$TIMERX::ptr() };
                        timer.icr().modify(|_, w| w.[<t $sub_type:lower tocint>]().set_bit());
                    }
                }

                )+

                impl GpTimerExt for $TIMERX {
                    type Parts = Parts;

                    fn split(self) -> Self::Parts {
                        Parts {
                            timer: $type {
                                cfg: Cfg,
                                ctl: Ctl,
                                sync: Sync,
                                imr: Imr,
                                ris: Ris,
                                mis: Mis,
                                icr: Icr,
                                pp: Pp,
                            },
                            $(
                            [<timer $sub_type:lower>]: [<Timer $sub_type>] {
                                mr: [<T $sub_type:lower mr>],
                                ilr: [<T $sub_type:lower ilr>],
                                matcher: [<T $sub_type:lower matchr>],
                                pr: [<T $sub_type:lower pr>],
                                pmr: [<T $sub_type:lower pmr>],
                                r: [<T $sub_type:lower r>],
                                v: [<T $sub_type:lower v>],
                                ps: [<T $sub_type:lower ps>],
                                pv: [<T $sub_type:lower pv>],
                                _state: PhantomData,
                                _type: PhantomData,
                            },
                            )+
                        }
                    }
                }

                timer_registers! {
                    [
                        ($TIMERX, $timerx, Cfg, cfg),
                        ($TIMERX, $timerx, Ctl, ctl),
                        ($TIMERX, $timerx, Sync, sync),
                        ($TIMERX, $timerx, Imr, imr),
                        ($TIMERX, $timerx, Ris, ris),
                        ($TIMERX, $timerx, Mis, mis),
                        ($TIMERX, $timerx, Icr, icr),
                        ($TIMERX, $timerx, Pp, pp),
                        $(
                        ($TIMERX, $timerx, [<T $sub_type:lower mr>], [<t $sub_type:lower mr>]),
                        ($TIMERX, $timerx, [<T $sub_type:lower ilr>], [<t $sub_type:lower ilr>]),
                        ($TIMERX, $timerx, [<T $sub_type:lower matchr>], [<t $sub_type:lower matchr>]),
                        ($TIMERX, $timerx, [<T $sub_type:lower pr>], [<t $sub_type:lower pr>]),
                        ($TIMERX, $timerx, [<T $sub_type:lower pmr>], [<t $sub_type:lower pmr>]),
                        ($TIMERX, $timerx, [<T $sub_type:lower r>], [<t $sub_type:lower r>]),
                        ($TIMERX, $timerx, [<T $sub_type:lower v>], [<t $sub_type:lower v>]),
                        ($TIMERX, $timerx, [<T $sub_type:lower ps>], [<t $sub_type:lower ps>]),
                        ($TIMERX, $timerx, [<T $sub_type:lower pv>], [<t $sub_type:lower pv>]),
                        )+
                    ]
                }
            }
        )+
        }
    };
}

timer!([
    {
        timer: Gptimer0,
        mapped: gptimer0,
        name: Timer0,
        module: timer0,
        [
            A,
            B
        ]
    },
    {
        timer: Gptimer1,
        mapped: gptimer1,
        name: Timer1,
        module: timer1,
        [
            A,
            B
        ]
    },
    {
        timer: Gptimer2,
        mapped: gptimer2,
        name: Timer2,
        module: timer2,
        [
            A,
            B
        ]
    },
    {
        timer: Gptimer3,
        mapped: gptimer3,
        name: Timer3,
        module: timer3,
        [
            A,
            B
        ]
    }
]);
