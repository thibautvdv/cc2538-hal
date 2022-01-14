use core::marker::PhantomData;

use crate::sys_ctrl::ClockConfig;
use cc2538_pac::{I2CM, I2CS};
use cortex_m::asm::delay;

use embedded_hal::i2c::blocking::*;
use embedded_hal::i2c::*;

#[derive(Debug)]
pub struct Disabled;
#[derive(Debug)]
pub struct Enabled;

#[derive(Debug)]
enum Operation {
    Read,
    Write,
}

#[derive(Debug)]
enum I2cCommand {
    BurstSendCont = 0x1,
    BurstSendStart = 0x3,
    BurstSendReceiveErrorStop = 0x4,
    BurstSendReceiveFinish = 0x5,
    SingleSendReceive = 0x7,
    BurstReceiveCont = 0x9,
    BurstReceiveStart = 0xb,
}

/// I2C Master extension trait.
pub trait I2cmExt {
    type Parts;
    fn take(self) -> Self::Parts;
}

/// I2C Slave extension trait.
pub trait I2csExt {
    type Parts;
    fn take(self) -> Self::Parts;
}

impl I2cmExt for I2CM {
    type Parts = I2cMaster<Disabled>;

    fn take(self) -> Self::Parts {
        I2cMaster {
            i2cm: self,
            _state: PhantomData,
        }
    }
}

#[derive(Debug)]
pub struct I2cMaster<STATE> {
    i2cm: I2CM,
    _state: PhantomData<STATE>,
}

impl<STATE> I2cMaster<STATE> {
    /// Set the slave address.
    /// Also sets the read/write flag.
    fn set_slave_address(&self, addr: u8, op: Operation) {
        match op {
            Operation::Read => unsafe {
                self.i2cm.sa.modify(|_, w| w.sa().bits(addr).rs().set_bit())
            },
            Operation::Write => unsafe {
                self.i2cm
                    .sa
                    .modify(|_, w| w.sa().bits(addr).rs().clear_bit())
            },
        }
    }
}

impl I2cMaster<Disabled> {
    /// Enable the I2C master module.
    pub fn enable(self) -> I2cMaster<Enabled> {
        self.i2cm.cr.modify(|_, w| w.mfe().set_bit());

        I2cMaster {
            i2cm: self.i2cm,
            _state: PhantomData,
        }
    }
}

impl I2cMaster<Enabled> {
    /// Set the bit rate of the I2C bus.
    pub fn set_bit_rate(&self, bit_rate: u32, clock_config: ClockConfig) {
        unsafe {
            self.i2cm.tpr.modify(|_, w| {
                w.tpr().bits(
                    ((clock_config.sys_freq() + (2 * 10 * bit_rate)) / (2 * 10 * bit_rate)) as u8
                        - 1,
                )
            });
        }
    }

    /// Write a command.
    fn write_command(&self, command: I2cCommand) {
        unsafe {
            self.i2cm.ctrl().write(|w| w.bits(command as u32));
        }
    }

    /// Get data from the data buffer.
    fn get_data(&self) -> u8 {
        self.i2cm.dr.read().data().bits()
    }

    /// Put data into the data buffer.
    fn put_data(&self, data: u8) {
        unsafe {
            self.i2cm.dr.write(|w| w.data().bits(data));
        }
    }

    /// Blocking single byte write.
    pub fn single_write(&self, addr: u8, data: u8) -> Result<(), ()> {
        self.set_slave_address(addr, Operation::Read);
        self.put_data(data);

        self.write_command(I2cCommand::SingleSendReceive);

        while self.is_busy() {}

        Ok(())
    }

    /// Blocking multiple bytes write.
    pub fn burst_write(&self, addr: u8, data: &[u8]) -> Result<(), ()> {
        if data.len() == 1 {
            return self.single_write(addr, data[0]);
        }

        self.set_slave_address(addr, Operation::Write);

        for (i, b) in data.iter().enumerate() {
            self.put_data(*b);

            if i == 0 {
                self.write_command(I2cCommand::BurstSendStart);
            } else if i == data.len() - 1 {
                self.write_command(I2cCommand::BurstSendReceiveFinish);
            } else {
                self.write_command(I2cCommand::BurstSendCont);
            }

            while self.is_busy() {}
        }

        Ok(())
    }

    /// Blocking single byte read.
    pub fn single_read(&self, addr: u8) -> Result<u8, ()> {
        self.set_slave_address(addr, Operation::Read);

        self.write_command(I2cCommand::SingleSendReceive);

        while self.is_busy() {}

        Ok(self.get_data())
    }

    /// Blocking multiple bytes read.
    pub fn burst_read(&self, addr: u8, buffer: &mut [u8]) -> Result<(), ()> {
        self.set_slave_address(addr, Operation::Read);
        self.write_command(I2cCommand::BurstReceiveStart);

        while self.is_busy() {}

        let len = buffer.len();
        for (i, b) in buffer.iter_mut().enumerate() {
            *b = self.get_data();

            // TODO(thvdveld): fix the last NACK
            if i == len - 1 {
                self.write_command(I2cCommand::BurstSendReceiveFinish);
                break;
            } else {
                self.write_command(I2cCommand::BurstReceiveCont);
            }

            while self.is_busy() {}
        }

        Ok(())
    }

    /// Check if the I2C bus is busy.
    pub fn is_busy(&self) -> bool {
        self.i2cm.stat().read().busy().bit_is_set()
    }
}

impl Write<SevenBitAddress> for I2cMaster<Enabled> {
    type Error = (); // TODO(thvdeld): implement errors

    fn write(&mut self, address: SevenBitAddress, bytes: &[u8]) -> Result<(), Self::Error> {
        self.burst_write(address, bytes)
    }
}

impl WriteRead<SevenBitAddress> for I2cMaster<Enabled> {
    type Error = (); // TODO(thvdveld): implement errors

    fn write_read(
        &mut self,
        address: SevenBitAddress,
        bytes: &[u8],
        buffer: &mut [u8],
    ) -> Result<(), Self::Error> {
        todo!()
    }
}

impl Read<SevenBitAddress> for I2cMaster<Enabled> {
    type Error = ();

    fn read(&mut self, address: SevenBitAddress, buffer: &mut [u8]) -> Result<(), Self::Error> {
        self.burst_read(address, buffer)
    }
}
