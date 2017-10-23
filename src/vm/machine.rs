#![allow(dead_code)]
extern crate byteorder;

use std::io::Cursor;

use self::byteorder::{BigEndian, NativeEndian, ReadBytesExt};

use instruction::*;

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
      _ => Err(()),
    };
    if ret.is_err() {
      return ret;
    }
    self.frame += match class {
      CLASS_JMP => {
        if self.accumulator == 0 {
          instr.jt as u32
        } else {
          instr.jf as u32
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
  pub fn run_program_bytes(&mut self, _: &[u8], _: &[u8]) -> Result<u32, ()> {
    unimplemented!()
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
}
