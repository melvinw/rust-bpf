#![allow(dead_code)]
extern crate rust_bpf;
extern crate byteorder;

use std::io::Cursor;
use std::slice;

use self::byteorder::{BigEndian, NativeEndian, ReadBytesExt};

use self::rust_bpf::common::instruction::*;

const SCRATCH_MEM_SLOTS: usize = 16;

pub struct PsuedoMachine {
  /// The frame pointer.
  frame: u32,
  /// The accumulator.
  accumulator: u32,
  /// The index register.
  index: u32,
  /// Scratch memory.
  memory: [u32; SCRATCH_MEM_SLOTS],
}

trait Testing {
  fn frame(&self) -> u32;
  fn accumulator(&self) -> u32;
  fn index(&self) -> u32;
  fn memory(&self) -> &[u32];
  fn set_frame(&mut self, frame: u32);
  fn set_accumulator(&mut self, acc: u32);
  fn set_index(&mut self, index: u32);
  fn set_memory(&mut self, idx: usize, val: u32);
}

impl Testing for PsuedoMachine {
  fn frame(&self) -> u32 {
    self.frame
  }

  fn accumulator(&self) -> u32 {
    self.accumulator
  }

  fn index(&self) -> u32 {
    self.index
  }

  fn memory(&self) -> &[u32] {
    &self.memory
  }

  fn set_frame(&mut self, frame: u32) {
    self.frame = frame;
  }

  fn set_accumulator(&mut self, acc: u32) {
    self.accumulator = acc;
  }

  fn set_index(&mut self, index: u32) {
    self.index = index;
  }

  fn set_memory(&mut self, idx: usize, val: u32) {
    self.memory[idx] = val;
  }
}

impl PsuedoMachine {
  /// Returns a zero-initialized PsuedoMachine.
  pub fn new() -> PsuedoMachine {
    PsuedoMachine {
      frame: 0,
      accumulator: 0,
      index: 0,
      memory: [0; 16],
    }
  }

  /// Resets all fields to zero.
  pub fn reset(&mut self) {
    self.frame = 0;
    self.accumulator = 0;
    self.index = 0;
    self.memory = [0; 16];
  }

  /// Return the value in scratch memory slot `n`.
  fn mem(&self, n: usize) -> u32 {
    assert!(n < SCRATCH_MEM_SLOTS);
    self.memory[n]
  }

  /// Helper for full word loads.
  #[inline]
  fn ld_u32(&mut self, offset: u32, buf: &[u8]) -> Result<u32, ()> {
    if offset as usize >= buf.len() {
      return Err(());
    }
    let mut cur = Cursor::new(&buf[offset as usize..]);
    let ret = cur.read_u32::<BigEndian>();
    if ret.is_err() {
      return Err(());
    }
    Ok(ret.unwrap())
  }

  /// Helper for half-words loads.
  #[inline]
  fn ld_u16(&mut self, offset: u32, buf: &[u8]) -> Result<u32, ()> {
    if offset as usize >= buf.len() {
      return Err(());
    }
    let mut cur = Cursor::new(&buf[offset as usize..]);
    let ret = cur.read_u16::<BigEndian>();
    if ret.is_err() {
      return Err(());
    }
    Ok(ret.unwrap() as u32)
  }

  /// Helper for single byte loads.
  #[inline]
  fn ld_u8(&mut self, offset: u32, buf: &[u8]) -> Result<u32, ()> {
    if offset as usize >= buf.len() {
      return Err(());
    }
    Ok(buf[offset as usize] as u32)
  }

  /// Execute an instruction and increments the frame pointer after successful execution.
  /// Returns Ok(Some) if `instr` is a return instruction.
  /// Returns Err on bad instruction.
  pub fn execute(&mut self, instr: &Instruction, pkt: &[u8]) -> Result<Option<u32>, ()> {
    let opcode = instr.opcode;
    let class = instr.class();
    let k = instr.k;
    let idx = self.index;

    let mut jmp_case = false;
    let ret = match opcode {
      LDI => {
        self.accumulator = k;
        Ok(None)
      },
      LDW => {
        self.accumulator = self.ld_u32(k, pkt)?;
        Ok(None)
      },
      LDWI => {
        self.accumulator = self.ld_u32(idx + k, pkt)?;
        Ok(None)
      },
      LDWM => {
        if k >= SCRATCH_MEM_SLOTS as u32 {
          return Err(());
        }
        self.accumulator = self.memory[k as usize];
        Ok(None)
      },
      LDH => {
        self.accumulator = self.ld_u16(k, pkt)?;
        Ok(None)
      },
      LDHI => {
        self.accumulator = self.ld_u16(idx + k, pkt)?;
        Ok(None)
      },
      LDHM => {
        if k >= SCRATCH_MEM_SLOTS as u32 {
          return Err(());
        }
        let val = self.memory[k as usize] & 0x0000FFFF;
        self.accumulator = val;
        Ok(None)
      },
      LDB => {
        self.accumulator = self.ld_u8(k, pkt)?;
        Ok(None)
      },
      LDBI => {
        self.accumulator = self.ld_u8(idx + k, pkt)?;
        Ok(None)
      },
      LDBM => {
        if k >= SCRATCH_MEM_SLOTS as u32 {
          return Err(());
        }
        let val = self.memory[k as usize] & 0x000000FF;
        self.accumulator = val;
        Ok(None)
      },
      LDXI => {
        self.index = k;
        Ok(None)
      },
      LDXL => {
        if k >= pkt.len() as u32 {
          Err(())
        } else {
          self.index = 4 * (pkt[k as usize] & 0x0F) as u32;
          Ok(None)
        }
      },
      ST => {
        if k >= SCRATCH_MEM_SLOTS as u32 {
          return Err(());
        }
        self.memory[k as usize] = self.accumulator;
        Ok(None)
      },
      STX => {
        if k >= SCRATCH_MEM_SLOTS as u32 {
          return Err(());
        }
        self.memory[k as usize] = self.index;
        Ok(None)
      },
      TXA => {
        self.accumulator = self.index;
        Ok(None)
      },
      TAX => {
        self.index = self.accumulator;
        Ok(None)
      },
      RETA => Ok(Some(self.accumulator)),
      RETK => Ok(Some(k)),
      ADDX => {
        self.accumulator += self.index;
        Ok(None)
      },
      SUBX => {
        self.accumulator -= self.index;
        Ok(None)
      },
      MULX => {
        if self.index == 0 {
          Err(())
        } else {
          self.accumulator *= self.index;
          Ok(None)
        }
      },
      DIVX => {
        self.accumulator /= self.index;
        Ok(None)
      },
      ORX => {
        self.accumulator |= self.index;
        Ok(None)
      },
      ANDX => {
        self.accumulator &= self.index;
        Ok(None)
      },
      LSHX => {
        self.accumulator <<= self.index;
        Ok(None)
      },
      RSHX => {
        self.accumulator >>= self.index;
        Ok(None)
      },
      MODX => {
        if self.index == 0 {
          Err(())
        } else {
          self.accumulator %= self.index;
          Ok(None)
        }
      },
      XORX => {
        self.accumulator ^= self.index;
        Ok(None)
      },
      ADDK => {
        self.accumulator += k;
        Ok(None)
      },
      SUBK => {
        self.accumulator -= k;
        Ok(None)
      },
      MULK => {
        self.accumulator *= k;
        Ok(None)
      },
      DIVK => {
        if k == 0 {
          Err(())
        } else {
          self.accumulator /= k;
          Ok(None)
        }
      },
      ORK => {
        self.accumulator |= k;
        Ok(None)
      },
      ANDK => {
        self.accumulator &= k;
        Ok(None)
      },
      LSHK => {
        self.accumulator <<= k;
        Ok(None)
      },
      RSHK => {
        self.accumulator >>= k;
        Ok(None)
      },
      MODK => {
        if k == 0 {
          Err(())
        } else {
          self.accumulator %= k;
          Ok(None)
        }
      },
      XORK => {
        self.accumulator ^= k;
        Ok(None)
      },
      NEG => {
        self.accumulator = !self.accumulator;
        Ok(None)
      },
      JMP => {
        self.frame = k;
        Ok(None)
      },
      JMPEQ => {
        jmp_case = self.accumulator == k;
        Ok(None)
      },
      JMPGT => {
        jmp_case = self.accumulator > k;
        Ok(None)
      },
      JMPGE => {
        jmp_case = self.accumulator >= k;
        Ok(None)
      },
      JMPSET => {
        jmp_case = (self.accumulator & k) > 0;
        Ok(None)
      },
      _ => Err(()),
    };
    if ret.is_err() {
      return ret;
    }
    self.frame += match class {
      CLASS_JMP => {
        if instr.op() != OP_JA && jmp_case {
          instr.jt as u32
        } else if instr.op() != OP_JA {
          instr.jf as u32
        } else {
          0
        }
      },
      _ => 1,
    };
    ret
  }

  /// Runs the program stored as a slice of instructions.
  /// Returns Ok with accept/reject if the program completes, Err otherwise.
  pub fn run_program(&mut self, prog: &[Instruction], pkt: &[u8]) -> Result<u32, ()> {
    loop {
      if self.frame as usize >= prog.len() {
        return Err(());
      }
      let ref instr = prog[self.frame as usize];
      let res = self.execute(instr, pkt);
      if res.is_err() {
        return Err(());
      }
      match res.unwrap() {
        Some(ret) => return Ok(ret),
        _ => continue,
      };
    }
  }

  /// Runs the program stored in a byte buffer.
  /// Returns Ok with accept/reject if the program completes, Err otherwise.
  pub fn run_program_bytes(&mut self, prog: &[u8], pkt: &[u8]) -> Result<u32, ()> {
    if prog.len() % 8 > 0 {
      return Err(());
    }
    let instrs = unsafe { slice::from_raw_parts(prog.as_ptr() as *const Instruction, prog.len() / 8) };
    self.run_program(instrs, pkt)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn ldi() {
    let mut pm = PsuedoMachine::new();
    let instr = Instruction::new(CLASS_LD | MODE_IMM | SIZE_W, 0, 0, 0xDEADBEEF);
    let pkt = [0 as u8; 64];
    let ret = pm.execute(&instr, &pkt);
    assert!(ret.unwrap() == None);
    assert!(pm.accumulator() == 0xDEADBEEF);
  }

  #[test]
  fn ldw() {
    let mut pm = PsuedoMachine::new();
    let mut pkt = [0 as u8; 64];
    pkt[3] = 0xDE;
    pkt[4] = 0xAD;
    pkt[5] = 0xBE;
    pkt[6] = 0xEF;
    let instr = Instruction::new(MODE_ABS | SIZE_W | CLASS_LD, 0, 0, 3);
    let ret = pm.execute(&instr, &pkt);
    assert!(ret.unwrap() == None);
    assert!(pm.accumulator() == 0xDEADBEEF);
  }

  #[test]
  fn ldwm() {
    let mut pm = PsuedoMachine::new();
    let pkt = [0 as u8; 64];
    pm.set_memory(5, 0xDEADBEEF);
    let instr = Instruction::new(MODE_MEM | SIZE_W | CLASS_LD, 0, 0, 5);
    let ret = pm.execute(&instr, &pkt);
    assert!(ret.unwrap() == None);
    assert!(pm.accumulator() == 0xDEADBEEF);
  }

  #[test]
  fn ldh() {
    let mut pm = PsuedoMachine::new();
    let mut pkt = [0 as u8; 64];
    pkt[3] = 0xDE;
    pkt[4] = 0xAD;
    pkt[5] = 0xBE;
    pkt[6] = 0xEF;
    let instr = Instruction::new(MODE_ABS | SIZE_H | CLASS_LD, 0, 0, 3);
    let ret = pm.execute(&instr, &pkt);
    assert!(ret.unwrap() == None);
    assert!(pm.accumulator() == 0xDEAD);
  }

  #[test]
  fn ldhm() {
    let mut pm = PsuedoMachine::new();
    let pkt = [0 as u8; 64];
    pm.set_memory(5, 0xDEADBEEF);
    let instr = Instruction::new(MODE_MEM | SIZE_H | CLASS_LD, 0, 0, 5);
    let ret = pm.execute(&instr, &pkt);
    assert!(ret.unwrap() == None);
    assert!(pm.accumulator() == 0xBEEF);
  }

  #[test]
  fn ldb() {
    let mut pm = PsuedoMachine::new();
    let mut pkt = [0 as u8; 64];
    pkt[3] = 0xDE;
    pkt[4] = 0xAD;
    pkt[5] = 0xBE;
    pkt[6] = 0xEF;
    let instr = Instruction::new(MODE_ABS | SIZE_B | CLASS_LD, 0, 0, 3);
    let ret = pm.execute(&instr, &pkt);
    assert!(ret.unwrap() == None);
    assert!(pm.accumulator() == 0xDE);
  }

  #[test]
  fn ldbm() {
    let mut pm = PsuedoMachine::new();
    let pkt = [0 as u8; 64];
    pm.set_memory(5, 0xDEADBEEF);
    let instr = Instruction::new(MODE_MEM | SIZE_B | CLASS_LD, 0, 0, 5);
    let ret = pm.execute(&instr, &pkt);
    assert!(ret.unwrap() == None);
    assert!(pm.accumulator() == 0xEF);
  }

  #[test]
  fn ldwi() {
    let mut pm = PsuedoMachine::new();
    let mut pkt = [0 as u8; 64];
    pkt[4] = 0xDE;
    pkt[5] = 0xAD;
    pkt[6] = 0xBE;
    pkt[7] = 0xEF;
    pm.set_index(1);
    let instr = Instruction::new(MODE_IND | SIZE_W | CLASS_LD, 0, 0, 3);
    let ret = pm.execute(&instr, &pkt);
    assert!(ret.unwrap() == None);
    assert!(pm.accumulator() == 0xDEADBEEF);
  }

  #[test]
  fn ldhi() {
    let mut pm = PsuedoMachine::new();
    let mut pkt = [0 as u8; 64];
    pkt[4] = 0xDE;
    pkt[5] = 0xAD;
    pkt[6] = 0xBE;
    pkt[7] = 0xEF;
    pm.set_index(1);
    let instr = Instruction::new(MODE_IND | SIZE_H | CLASS_LD, 0, 0, 3);
    let ret = pm.execute(&instr, &pkt);
    assert!(ret.unwrap() == None);
    assert!(pm.accumulator() == 0xDEAD);
  }

  #[test]
  fn ldbi() {
    let mut pm = PsuedoMachine::new();
    let mut pkt = [0 as u8; 64];
    pkt[4] = 0xDE;
    pkt[5] = 0xAD;
    pkt[6] = 0xBE;
    pkt[7] = 0xEF;
    pm.set_index(1);
    let instr = Instruction::new(MODE_IND | SIZE_B | CLASS_LD, 0, 0, 3);
    let ret = pm.execute(&instr, &pkt);
    assert!(ret.unwrap() == None);
    assert!(pm.accumulator() == 0xDE);
  }

  #[test]
  fn ldxi() {
    let mut pm = PsuedoMachine::new();
    let instr = Instruction::new(MODE_IMM | SIZE_W | CLASS_LDX, 0, 0, 14);
    let pkt = [0 as u8; 64];
    let ret = pm.execute(&instr, &pkt);
    assert!(ret.unwrap() == None);
    assert!(pm.index() == 14);
  }

  #[test]
  fn ldxl() {
    let mut pm = PsuedoMachine::new();
    let instr = Instruction::new(MODE_LEN | SIZE_W | SIZE_B | CLASS_LDX, 0, 0, 3);
    let mut pkt = [0 as u8; 64];
    pkt[3] = 0x1A;
    let ret = pm.execute(&instr, &pkt);
    assert!(ret.unwrap() == None);
    assert!(pm.index() == 40);
  }

  #[test]
  fn st() {
    let mut pm = PsuedoMachine::new();
    let instr = Instruction::new(MODE_MEM | CLASS_ST, 0, 0, 8);
    let pkt = [0 as u8; 64];
    pm.set_accumulator(0xDEADBEEF);
    let ret = pm.execute(&instr, &pkt);
    assert!(ret.unwrap() == None);
    assert!(pm.memory()[8] == 0xDEADBEEF);
  }

  #[test]
  fn stx() {
    let mut pm = PsuedoMachine::new();
    let instr = Instruction::new(MODE_MEM | CLASS_STX, 0, 0, 8);
    let pkt = [0 as u8; 64];
    pm.set_index(0xDEADBEEF);
    let ret = pm.execute(&instr, &pkt);
    assert!(ret.unwrap() == None);
    assert!(pm.memory()[8] == 0xDEADBEEF);
  }

  #[test]
  fn txa() {
    let mut pm = PsuedoMachine::new();
    let instr = Instruction::new(CLASS_MISC | OP_TXA, 0, 0, 0);
    let pkt = [0 as u8; 64];
    pm.set_index(0xDEADBEEF);
    let ret = pm.execute(&instr, &pkt);
    assert!(ret.unwrap() == None);
    assert!(pm.accumulator() == 0xDEADBEEF);
  }

  #[test]
  fn tax() {
    let mut pm = PsuedoMachine::new();
    let instr = Instruction::new(CLASS_MISC | OP_TAX, 0, 0, 0);
    let pkt = [0 as u8; 64];
    pm.set_accumulator(0xDEADBEEF);
    let ret = pm.execute(&instr, &pkt);
    assert!(ret.unwrap() == None);
    assert!(pm.index() == 0xDEADBEEF);
  }

  #[test]
  fn reta() {
    let mut pm = PsuedoMachine::new();
    let instr = Instruction::new(CLASS_RET | RVAL_A, 0, 0, 0);
    let pkt = [0 as u8; 64];
    pm.set_accumulator(0xDEADBEEF);
    let ret = pm.execute(&instr, &pkt);
    assert!(ret.unwrap().unwrap() == 0xDEADBEEF);
  }

  #[test]
  fn retk() {
    let mut pm = PsuedoMachine::new();
    let instr = Instruction::new(CLASS_RET | RVAL_K, 0, 0, 0xDEADBEEF);
    let pkt = [0 as u8; 64];
    let ret = pm.execute(&instr, &pkt);
    assert!(ret.unwrap().unwrap() == 0xDEADBEEF);
  }

  #[test]
  fn alu_index() {
    let mut pm = PsuedoMachine::new();
    let pkt = [0 as u8; 64];
    let prog = vec![
      Instruction::new(CLASS_ALU | OP_NEG, 0, 0, 0),
      Instruction::new(CLASS_ALU | SRC_X | OP_XOR, 0, 0, 0),
      Instruction::new(CLASS_ALU | SRC_X | OP_ADD, 0, 0, 0),
      Instruction::new(CLASS_ALU | SRC_X | OP_SUB, 0, 0, 0),
      Instruction::new(CLASS_ALU | SRC_X | OP_MUL, 0, 0, 0),
      Instruction::new(CLASS_ALU | SRC_X | OP_DIV, 0, 0, 0),
      Instruction::new(CLASS_ALU | SRC_X | OP_OR, 0, 0, 0),
      Instruction::new(CLASS_ALU | SRC_X | OP_AND, 0, 0, 0),
      Instruction::new(CLASS_ALU | SRC_X | OP_LSH, 0, 0, 0),
      Instruction::new(CLASS_ALU | SRC_X | OP_RSH, 0, 0, 0),
      Instruction::new(CLASS_RET | RVAL_A, 0, 0, 0),
    ];
    pm.set_accumulator(!0xBEEF);
    pm.set_index(2);
    let ret = pm.run_program(prog.as_slice(), &pkt).unwrap();
    let mut expected = 0xBEEF;
    expected ^= 2;
    expected += 2;
    expected -= 2;
    expected *= 2;
    expected |= 2;
    expected &= 2;
    expected <<= 2;
    expected >>= 2;
    assert!(ret == expected);
    let mod_instr = Instruction::new(CLASS_ALU | SRC_X | OP_MOD, 0, 0, 0);
    pm.execute(&mod_instr, &pkt).unwrap();
    assert!(pm.accumulator() == expected % 2);
  }

  #[test]
  fn alu_imm() {
    let mut pm = PsuedoMachine::new();
    let pkt = [0 as u8; 64];
    let prog = vec![
      Instruction::new(CLASS_ALU | OP_NEG, 0, 0, 0),
      Instruction::new(CLASS_ALU | SRC_K | OP_XOR, 0, 0, 2),
      Instruction::new(CLASS_ALU | SRC_K | OP_ADD, 0, 0, 2),
      Instruction::new(CLASS_ALU | SRC_K | OP_SUB, 0, 0, 2),
      Instruction::new(CLASS_ALU | SRC_K | OP_MUL, 0, 0, 2),
      Instruction::new(CLASS_ALU | SRC_K | OP_DIV, 0, 0, 2),
      Instruction::new(CLASS_ALU | SRC_K | OP_OR, 0, 0, 2),
      Instruction::new(CLASS_ALU | SRC_K | OP_AND, 0, 0, 2),
      Instruction::new(CLASS_ALU | SRC_K | OP_LSH, 0, 0, 2),
      Instruction::new(CLASS_ALU | SRC_K | OP_RSH, 0, 0, 2),
      Instruction::new(CLASS_RET | RVAL_A, 0, 0, 0),
    ];
    pm.set_accumulator(!0xBEEF);
    let ret = pm.run_program(prog.as_slice(), &pkt).unwrap();
    let mut expected = 0xBEEF;
    expected ^= 2;
    expected += 2;
    expected -= 2;
    expected *= 2;
    expected |= 2;
    expected &= 2;
    expected <<= 2;
    expected >>= 2;
    assert!(ret == expected);
    let mod_instr = Instruction::new(CLASS_ALU | SRC_K | OP_MOD, 0, 0, 2);
    pm.execute(&mod_instr, &pkt).unwrap();
    assert!(pm.accumulator() == expected % 2);
  }

  #[test]
  fn jump() {
    let mut pm = PsuedoMachine::new();
    let pkt = [0 as u8; 64];
    let mut instr = Instruction::new(CLASS_JMP | OP_JA, 0, 0, 10);
    pm.set_accumulator(100);
    pm.execute(&instr, &pkt).unwrap();
    assert!(pm.frame() == 10);
    instr = Instruction::new(CLASS_JMP | OP_JEQ, 2, 1, 100);
    pm.execute(&instr, &pkt).unwrap();
    assert!(pm.frame() == 12);
    instr = Instruction::new(CLASS_JMP | OP_JEQ, 1, 2, 3);
    pm.execute(&instr, &pkt).unwrap();
    assert!(pm.frame() == 14);
    instr = Instruction::new(CLASS_JMP | OP_JGT, 2, 1, 99);
    pm.execute(&instr, &pkt).unwrap();
    assert!(pm.frame() == 16);
    instr = Instruction::new(CLASS_JMP | OP_JGE, 2, 1, 99);
    pm.execute(&instr, &pkt).unwrap();
    assert!(pm.frame() == 18);
    instr = Instruction::new(CLASS_JMP | OP_JGE, 2, 1, 100);
    pm.execute(&instr, &pkt).unwrap();
    assert!(pm.frame() == 20);
    instr = Instruction::new(CLASS_JMP | OP_JSET, 2, 1, 100);
    pm.execute(&instr, &pkt).unwrap();
    assert!(pm.frame() == 22);
  }

  #[test]
  fn run_bytecode() {
    let mut pm = PsuedoMachine::new();
    let pkt = [0 as u8; 64];
    let prog = vec![
      Instruction::new(MODE_IMM | CLASS_LD, 0, 0, 0xBEEF),
      Instruction::new(CLASS_ALU | OP_NEG, 0, 0, 0),
      Instruction::new(CLASS_ALU | SRC_K | OP_XOR, 0, 0, 0xDEAD),
      Instruction::new(CLASS_RET | RVAL_A, 0, 0, 0),
    ];
    let prog_bytes = unsafe { slice::from_raw_parts(prog.as_slice().as_ptr() as *const u8, 32) };
    let ret = pm.run_program_bytes(prog_bytes, &pkt).unwrap();
    let expected = !0xBEEF ^ 0xDEAD;
    assert!(ret == expected);
  }
}
