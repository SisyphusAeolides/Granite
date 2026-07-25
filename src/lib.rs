#![no_std]

//! Native Granite loader primitives shared by the UEFI entry point and the
//! host-side contract tests. Nothing in this crate delegates ELF admission to
//! a firmware parser: the same bounded parser supplies the load plan that the
//! later placement stage will consume.

pub mod elf;
