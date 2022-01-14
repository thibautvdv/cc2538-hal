//! Input Output control

use core::convert::Infallible;
use core::marker::PhantomData;

use paste::paste;

pub trait IocExt {
    type Parts;

    fn split(self) -> Self::Parts;
}

macro_rules! ioc {
    (
        IOC: $IOC:ident,
        $(
            ($padover:ident, $padsel:ident),
        )+
        $(
            $pad_out_reg:ident,
        )+
    ) => {
        paste! {
            use crate::pac::$IOC;

            pub struct Parts {
                $(
                pub $padover: [<$padover:camel>],
                pub $padsel: [<$padsel:camel>],
                )+
                $(
                pub $pad_out_reg: [<$pad_out_reg:camel>],
                )+
            }

            $(
            pub struct [<$padover:camel>];
            impl [<$padover:camel>] {
                pub(crate) fn $padover(&mut self) -> &crate::pac::ioc::[<$padover:upper>] {
                    unsafe { &(*$IOC::ptr()).$padover }
                }
            }

            pub struct [<$padsel:camel>];
            impl [<$padsel:camel>] {
                pub(crate) fn $padsel(&mut self) -> &crate::pac::ioc::[<$padsel:upper>] {
                    unsafe { &(*$IOC::ptr()).$padsel }
                }
            }
            )+

            $(
            pub struct [<$pad_out_reg:camel>];
            impl [<$pad_out_reg:camel>] {
                pub(crate) fn $pad_out_reg(&mut self) -> &crate::pac::ioc::[<$pad_out_reg:upper>] {
                    unsafe { &(*$IOC::ptr()).$pad_out_reg }
                }
            }
            )+

            impl IocExt for $IOC {
                type Parts = Parts;

                fn split(self) -> Parts {
                    Parts {
                        $(
                        $padover: [<$padover:camel>],
                        $padsel: [<$padsel:camel>],
                        )+
                        $(
                        $pad_out_reg: [<$pad_out_reg:camel>],
                        )+
                    }
                }
            }
        }
    };
}

ioc!(
    IOC: IOC,
    (pa0_over, pa0_sel),
    (pa1_over, pa1_sel),
    (pa2_over, pa2_sel),
    (pa3_over, pa3_sel),
    (pa4_over, pa4_sel),
    (pa5_over, pa5_sel),
    (pa6_over, pa6_sel),
    (pa7_over, pa7_sel),
    (pb0_over, pb0_sel),
    (pb1_over, pb1_sel),
    (pb2_over, pb2_sel),
    (pb3_over, pb3_sel),
    (pb4_over, pb4_sel),
    (pb5_over, pb5_sel),
    (pb6_over, pb6_sel),
    (pb7_over, pb7_sel),
    (pc0_over, pc0_sel),
    (pc1_over, pc1_sel),
    (pc2_over, pc2_sel),
    (pc3_over, pc3_sel),
    (pc4_over, pc4_sel),
    (pc5_over, pc5_sel),
    (pc6_over, pc6_sel),
    (pc7_over, pc7_sel),
    (pd0_over, pd0_sel),
    (pd1_over, pd1_sel),
    (pd2_over, pd2_sel),
    (pd3_over, pd3_sel),
    (pd4_over, pd4_sel),
    (pd5_over, pd5_sel),
    (pd6_over, pd6_sel),
    (pd7_over, pd7_sel),
    uartrxd_uart0,
    uartcts_uart1,
    uartrxd_uart1,
    clk_ssi_ssi0,
    ssirxd_ssi0,
    ssifssin_ssi0,
    clk_ssiin_ssi0,
    clk_ssi_ssi1,
    ssirxd_ssi1,
    ssifssin_ssi1,
    clk_ssiin_ssi1,
    i2cmssda,
    i2cmsscl,
    gpt0ocp1,
    gpt0ocp2,
    gpt1ocp1,
    gpt1ocp2,
    gpt2ocp1,
    gpt2ocp2,
    gpt3ocp1,
    gpt3ocp2,
);
