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

  /// Load into the accumulator.
  fn ld_u32(&mut self, mode: u16, k: u32, pkt: &[u8]) -> Result<Option<u32>, ()> {
    match mode {
      MODE_IMM => {
        self.accumulator = k;
        Ok(None)
      },
      MODE_ABS => {
        if k as usize >= pkt.len() {
          return Err(());
        }
        let mut cur = Cursor::new(&pkt[k as usize..]);
        let ret = cur.read_u32::<BigEndian>();
        if ret.is_err() {
          return Err(());
        }
        self.accumulator = ret.unwrap();
        Ok(None)
      },
      MODE_IND => {
        let offset: usize = (self.index + k) as usize;
        if offset >= pkt.len() {
          return Err(());
        }
        let mut cur = Cursor::new(&pkt[offset as usize..]);
        let ret = cur.read_u32::<BigEndian>();
        if ret.is_err() {
          return Err(());
        }
        self.accumulator = ret.unwrap();
        Ok(None)
      },
      _ => Err(()),
    }
  }

  /// Execute an instruction and increments the frame pointer after successful execution.
  /// Returns Ok(Some) if `instr` is a return instruction.
  /// Returns Err on bad instruction.
  pub fn execute(&mut self, instr: &Instruction, pkt: &[u8]) -> Result<Option<u32>, ()> {
    let opcode = instr.opcode;
    let mode = instr.mode();
    let class = instr.class();
    let k = instr.k;
    let ret = match opcode {
      CLASS_LD | MODE_IMM | SIZE_W => self.ld_u32(mode, k, pkt),
      CLASS_LD | MODE_ABS | SIZE_W => self.ld_u32(mode, k, pkt),
      CLASS_LD | MODE_IND | SIZE_W => self.ld_u32(mode, k, pkt),
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
  pub fn run_program_bytes(&mut self, prog: &[u8], pkt: &[u8]) -> Result<u32, ()> {
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
  fn ld() {
    let mut pm = PsuedoMachine::new();
    let instr = Instruction::new(CLASS_LD | MODE_ABS | SIZE_W, 0, 0, 3);
    let mut pkt = [0 as u8; 64];
    pkt[3] = 0xDE;
    pkt[4] = 0xAD;
    pkt[5] = 0xBE;
    pkt[6] = 0xEF;
    let ret = pm.execute(&instr, &pkt);
    assert!(ret.unwrap() == None);
    println!("{:8X}", pm.accumulator());
    assert!(pm.accumulator() == 0xDEADBEEF);
  }

  #[test]
  fn ld_indirect() {
    let mut pm = PsuedoMachine::new();
    pm.set_index(1);
    let instr = Instruction::new(CLASS_LD | MODE_IND | SIZE_W, 0, 0, 3);
    let mut pkt = [0 as u8; 64];
    pkt[4] = 0xDE;
    pkt[5] = 0xAD;
    pkt[6] = 0xBE;
    pkt[7] = 0xEF;
    let ret = pm.execute(&instr, &pkt);
    assert!(ret.unwrap() == None);
    println!("{:8X}", pm.accumulator());
    assert!(pm.accumulator() == 0xDEADBEEF);
  }
}
