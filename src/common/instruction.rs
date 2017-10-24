#![allow(dead_code)]
extern crate byteorder;

use std::io::Cursor;
use std::mem;

use self::byteorder::{NativeEndian, ReadBytesExt};

// Class
pub const CLASS_LD: u16 = 0x00;
pub const CLASS_LDX: u16 = 0x01;
pub const CLASS_ST: u16 = 0x02;
pub const CLASS_STX: u16 = 0x03;
pub const CLASS_ALU: u16 = 0x04;
pub const CLASS_JMP: u16 = 0x05;
pub const CLASS_RET: u16 = 0x06;
pub const CLASS_MISC: u16 = 0x07;

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
pub const OP_ADD: u16 = 0x00;
pub const OP_SUB: u16 = 0x10;
pub const OP_MUL: u16 = 0x20;
pub const OP_DIV: u16 = 0x30;
pub const OP_OR: u16 = 0x40;
pub const OP_AND: u16 = 0x50;
pub const OP_LSH: u16 = 0x60;
pub const OP_RSH: u16 = 0x70;
pub const OP_NEG: u16 = 0x80;
pub const OP_MOD: u16 = 0x90;
pub const OP_XOR: u16 = 0xA0;

// Jump
pub const OP_JA: u16 = 0x00;
pub const OP_JEQ: u16 = 0x10;
pub const OP_JGT: u16 = 0x20;
pub const OP_JGE: u16 = 0x30;
pub const OP_JSET: u16 = 0x40;

// Misc
pub const OP_TAX: u16 = 0x00;
pub const OP_TXA: u16 = 0x80;

// Source
pub const SRC_K: u16 = 0x00;
pub const SRC_X: u16 = 0x08;

// Retval
pub const RVAL_A: u16 = 0x10;
pub const RVAL_K: u16 = 0x00;

// Helpful masks
pub const MASK_CLASS: u16 = 0x07;
pub const MASK_SIZE: u16 = 0x18;
pub const MASK_MODE: u16 = 0xe0;
pub const MASK_OP: u16 = 0xf0;
pub const MASK_SRC: u16 = 0x08;
pub const MASK_RVAL: u16 = 0x18;
pub const MASK_MISCOP: u16 = 0xf8;

// Mnemonics
/// Load an immediate into the accumulator
pub const LDI: u16 = MODE_IMM | CLASS_LD;

/// Load a word into the accumulator
pub const LDW: u16 = MODE_ABS | SIZE_W | CLASS_LD;
/// Load a word into the accumulator with indirection
pub const LDWI: u16 = MODE_IND | SIZE_W | CLASS_LD;
/// Load a word into the accumulator from scratch memory
pub const LDWM: u16 = MODE_MEM | SIZE_W | CLASS_LD;

/// Load a half-word into the accumulator
pub const LDH: u16 = MODE_ABS | SIZE_H | CLASS_LD;
/// Load a half-word into the accumulator with indirection
pub const LDHI: u16 = MODE_IND | SIZE_H | CLASS_LD;
/// Load a half-word into the accumulator from scratch memory
pub const LDHM: u16 = MODE_MEM | SIZE_H | CLASS_LD;

/// Load a byte into the accumulator
pub const LDB: u16 = MODE_ABS | SIZE_B | CLASS_LD;
/// Load a byte into the accumulator with indirection
pub const LDBI: u16 = MODE_IND | SIZE_B | CLASS_LD;
/// Load a byte into the accumulator from scratch memory
pub const LDBM: u16 = MODE_MEM | SIZE_B | CLASS_LD;

/// Load an immediate into the index register
pub const LDXI: u16 = MODE_IMM | SIZE_W | CLASS_LDX;

/// Load 4 * (pkt[k] & 0x0F) into the index register
pub const LDXL: u16 = MODE_LEN | SIZE_W | SIZE_B | CLASS_LDX;

/// Copy the contents of the accumulator to a scratch memory slot
pub const ST: u16 = MODE_MEM | CLASS_ST;

/// Copy the contents of the index register to a scratch memory slot
pub const STX: u16 = MODE_MEM | CLASS_STX;

/// Copy the contents of the index register to the accumulator
pub const TXA: u16 = CLASS_MISC | OP_TXA;

/// Copy the contents of the accumulator to the index register
pub const TAX: u16 = CLASS_MISC | OP_TAX;

/// Return the contents of the accumulator
pub const RETA: u16 = CLASS_RET | RVAL_A;
/// Return the operand
pub const RETK: u16 = CLASS_RET;

/// Arithmetic with index register as operand
pub const ADDX: u16 = CLASS_ALU | SRC_X | OP_ADD;
pub const SUBX: u16 = CLASS_ALU | SRC_X | OP_SUB;
pub const MULX: u16 = CLASS_ALU | SRC_X | OP_MUL;
pub const DIVX: u16 = CLASS_ALU | SRC_X | OP_DIV;
pub const ORX: u16 = CLASS_ALU | SRC_X | OP_OR;
pub const ANDX: u16 = CLASS_ALU | SRC_X | OP_AND;
pub const LSHX: u16 = CLASS_ALU | SRC_X | OP_LSH;
pub const RSHX: u16 = CLASS_ALU | SRC_X | OP_RSH;
pub const MODX: u16 = CLASS_ALU | SRC_X | OP_MOD;
pub const XORX: u16 = CLASS_ALU | SRC_X | OP_XOR;

/// Arithmetic with immediate as operand
pub const ADDK: u16 = CLASS_ALU | SRC_K | OP_ADD;
pub const SUBK: u16 = CLASS_ALU | SRC_K | OP_SUB;
pub const MULK: u16 = CLASS_ALU | SRC_K | OP_MUL;
pub const DIVK: u16 = CLASS_ALU | SRC_K | OP_DIV;
pub const ORK: u16 = CLASS_ALU | SRC_K | OP_OR;
pub const ANDK: u16 = CLASS_ALU | SRC_K | OP_AND;
pub const LSHK: u16 = CLASS_ALU | SRC_K | OP_LSH;
pub const RSHK: u16 = CLASS_ALU | SRC_K | OP_RSH;
pub const MODK: u16 = CLASS_ALU | SRC_K | OP_MOD;
pub const XORK: u16 = CLASS_ALU | SRC_K | OP_XOR;

/// Store the bitwise negation of the accumulator's value in the accumulator
pub const NEG: u16 = CLASS_ALU | OP_NEG;

/// Set the frame pointer to an immediate
pub const JMP: u16 = CLASS_JMP | OP_JA;

/// Conditional jumps
pub const JMPEQ: u16 = CLASS_JMP | OP_JEQ;
pub const JMPGT: u16 = CLASS_JMP | OP_JGT;
pub const JMPGE: u16 = CLASS_JMP | OP_JGE;
pub const JMPSET: u16 = CLASS_JMP | OP_JSET;

/// A BPF psuedo-machine instruction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Instruction {
  /// The opcode. Layout:
  /// +--------+--------+-------------------+
  /// | 3 bits | 2 bits |   3 bits          |
  /// |  mode  |  size  | instruction class |
  /// +--------+--------+-------------------+
  pub opcode: u16,
  /// Offset of next instruction for true branch of jumps.
  pub jt: u8,
  /// Offset of next instruction for false branch of jumps.
  pub jf: u8,
  /// General purpose thing.
  pub k: u32,
}

impl Instruction {
  /// Constructor for convenience
  pub fn new(opcode: u16, jt: u8, jf: u8, k: u32) -> Instruction {
    Instruction {
      opcode: opcode,
      jt: jt,
      jf: jf,
      k: k,
    }
  }

  /// Decodes an instruction from a byte buffer.
  /// Returns None if the instruction is ilformed.
  pub fn from_bytes(buf: &[u8]) -> Option<Instruction> {
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

    Some(Instruction {
      opcode: opcode,
      jt: jt,
      jf: jf,
      k: k,
    })
  }

  /// Decodes an instruction from a u64 in host byte order.
  #[inline]
  pub fn from_u64(val: u64) -> Instruction {
    unsafe { mem::transmute(val) }
  }

  /// Returns the operator class.
  #[inline]
  pub fn class(&self) -> u16 {
    self.opcode & MASK_CLASS
  }

  /// Returns the whether the operator operates on a byte, half-word or word.
  #[inline]
  pub fn size(&self) -> u16 {
    self.opcode & MASK_SIZE
  }

  /// Returns the operator's addressing mode.
  #[inline]
  pub fn mode(&self) -> u16 {
    self.opcode & MASK_MODE
  }

  /// Returns the encoded operator.
  #[inline]
  pub fn op(&self) -> u16 {
    self.opcode & MASK_OP
  }

  /// Returns the source of the operator's argument(s).
  #[inline]
  pub fn src(&self) -> u16 {
    self.opcode & MASK_SRC
  }

  /// Returns where the return value comes from.
  #[inline]
  pub fn rval(&self) -> u16 {
    self.opcode & MASK_RVAL
  }

  /// Returns one of the register transfer functions.
  #[inline]
  pub fn miscop(&self) -> u16 {
    self.opcode & MASK_MISCOP
  }
}
