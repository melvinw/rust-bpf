#![allow(dead_code)]
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
}

impl PsuedoMachine {
    /// Returns a zero-initialized PsuedoMachine.
    pub fn new() -> PsuedoMachine {
        PsuedoMachine{frame: 0, accumulator: 0, index:0, memory: [0; 16]}
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

    /// Execute an instruction.
    /// Returns Ok(Some) if `instr` is a return instruction.
    /// Returns Err on bad instruction.
    pub fn execute(&mut self, instr: &Instruction, pkt: &[u8]) -> Result<Option<u32>, ()> {
        Ok(None)
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
                _ => continue
            };
        }
    }

    /// Runs the program stored in a byte buffer.
    /// Returns Ok with accept/reject if the program completes, Err otherwise.
    pub fn run_program_bytes(&mut self, prog: &[u8], pkt: &[u8]) -> Result<u32, ()> {
        Ok(0)
    }
}