#![allow(dead_code)]
extern crate byteorder;

use std::io::Cursor;
use std::mem;

use self::byteorder::{NativeEndian, ReadBytesExt};

// Class
pub const CLASS_LD: u16     = 0x00;
pub const CLASS_LDX: u16    = 0x01;
pub const CLASS_ST: u16     = 0x02;
pub const CLASS_STX: u16    = 0x03;
pub const CLASS_ALU: u16    = 0x04;
pub const CLASS_JMP: u16    = 0x05;
pub const CLASS_RET: u16    = 0x06;
pub const CLASS_MISC: u16   = 0x07;

// Size
pub const SIZE_W: u16 = 0x00;
pub const SIZE_H: u16 = 0x08;
pub const SIZE_B: u16 = 0x10;

// Mode
pub const MODE_IMM: u16 = 0x00;
pub const MODE_ABS: u16 = 0x20;
pub const MODE_IND: u16 = 0x40;
pub const MODE_MEM: u16 = 0x60;
pub const MODE_LEN: u16 = 0x80;
pub const MODE_MSH: u16 = 0xA0;

// Arithmetic
pub const OP_ADD: u16   = 0x00;
pub const OP_SUB: u16   = 0x10;
pub const OP_MUL: u16   = 0x20;
pub const OP_DIV: u16   = 0x30;
pub const OP_OR: u16    = 0x40;
pub const OP_AND: u16   = 0x50;
pub const OP_LSH: u16   = 0x60;
pub const OP_RSH: u16   = 0x70;
pub const OP_NEG: u16   = 0x80;
pub const OP_MOD: u16   = 0x90;
pub const OP_XOR: u16   = 0xA0;

// Jump
pub const OP_JA: u16    = 0x00;
pub const OP_JEQ: u16   = 0x10;
pub const OP_JGT: u16   = 0x20;
pub const OP_JGE: u16   = 0x30;
pub const OP_JSET: u16  = 0x40;

// Misc
pub const OP_TAX: u16 = 0x00;
pub const OP_TXA: u16 = 0x80;

// Source
pub const SRC_K: u16 = 0x00;
pub const SRC_X: u16 = 0x08;

// Retval
pub const RVAL_A: u16 = 0x10;

/// A BPF psuedo-machine instruction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Instruction {
    /// The opcode.
    pub opcode: u16,
    /// Offset of next instruction for true branch of jumps.
    pub jt: u8,
    /// Offset of next instruction for false branch of jumps.
    pub jf: u8,
    /// General purpose thing.
    pub k: u32,
}

impl Instruction {
    /// Decodes an instruction from a byte buffer.
    /// Returns None if the instruction is ilformed.
    fn from_bytes(buf: &[u8]) -> Option<Instruction> {
        let mut cur = Cursor::new(buf);

        let opcode_res = cur.read_u16::<NativeEndian>();
        if opcode_res.is_err() {
            return None;
        }
        let opcode = opcode_res.unwrap();
        
        let jt_res = cur.read_u8();
        let jf_res = cur.read_u8();
        if jt_res.is_err() || jf_res.is_err() {
            return None;
        }
        let jt = jt_res.unwrap();
        let jf = jf_res.unwrap();

        let k_res = cur.read_u32::<NativeEndian>();
        if k_res.is_err() {
            return None;
        }
        let k = k_res.unwrap();

        Some(Instruction{opcode: opcode, jt: jt, jf: jf, k: k})
    }

    /// Decodes an instruction from a u64 in host byte order.
    fn from_u64(val: u64) -> Instruction {
        unsafe { mem::transmute(val) }
    }

    /// Returns the operator class.
    fn class(&self) -> u16 {
        self.opcode & 0x07
    }

    /// Returns the whether the operator operates on a byte, half-word or word.
    fn size(&self) -> u16 {
        self.opcode & 0x18
    }

    /// Returns the operator's addressing mode.
    fn mode(&self) -> u16 {
        self.opcode & 0xe0
    }

    /// Returns the encoded operator.
    fn op(&self) -> u16 {
       self.opcode & 0xf0
    }

    /// Returns the source of the operator's argument(s).
    fn src(&self) -> u16 {
        self.opcode & 0x08
    }

    /// Returns where the return value comes from.
    fn rval(&self) -> u16 {
        self.opcode & 0x18
    }

    /// Returns one of the register transfer functions.
    fn miscop(&self) -> u16 {
        self.opcode & 0xf8
    }
}
