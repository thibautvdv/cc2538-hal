//! This crate defines the HAL for the CC2538.

#![no_std]
#![feature(adt_const_params)]
#![allow(dead_code)]
#![allow(incomplete_features)]
#![allow(unused_imports)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use cc2538_pac as pac;
use cortex_m::peripheral::DWT;
use embedded_hal as hal;

pub mod adc;
pub mod crypto;
pub mod delay;
pub mod dma;
pub mod gpio;
pub mod i2c;
pub mod ioc;
pub mod radio;
pub mod rng;
pub mod serial;
pub mod smwd;
pub mod spi;
pub mod sys_ctrl;
pub mod time;
pub mod timers;

/// Get the IEEE address from fixed memory.
pub fn get_ieee_address(addr: &mut [u8]) {
    const TI_ADDR: [u8; 3] = [0x00, 0x12, 0x4b];
    const ADDR_LOCATION: u32 = 0x00280028;

    if unsafe { core::ptr::read((ADDR_LOCATION + 3) as *const u32) as u8 } == TI_ADDR[0]
        && unsafe { core::ptr::read((ADDR_LOCATION + 2) as *const u32) as u8 } == TI_ADDR[1]
        && unsafe { core::ptr::read((ADDR_LOCATION + 1) as *const u32) as u8 } == TI_ADDR[2]
    {
        for i in 0..8 {
            addr[8 - i - 1] = unsafe {
                core::ptr::read(
                    (ADDR_LOCATION + if i < 4 { i + 4 } else { i - 4 } as u32) as *const u32,
                )
            } as u8;
        }
    } else {
        for (i, b) in addr.iter_mut().enumerate() {
            *b = unsafe { core::ptr::read((ADDR_LOCATION + 8 - 1 - i as u32) as *const u32) } as u8;
        }
    }
}

struct FlashCca {
    _bootloader_backdoor_disable: u32,
    _is_valid: u32,
    _flash_start_addr: u32,
    _padding: u32,
}

#[link_section = ".flash_cca"]
#[used]
#[no_mangle]
static FLASH_CCA: FlashCca = FlashCca {
    _bootloader_backdoor_disable: 0xF3FF_FFFF,
    _is_valid: 0,
    _flash_start_addr: 0x0020_0000,
    _padding: 0xFFFF_FFFF,
};
