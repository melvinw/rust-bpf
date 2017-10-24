#[macro_use]
extern crate lazy_static;
extern crate rust_bpf;
extern crate regex;

use regex::Regex;
use std::collections::HashMap;
use std::fs::File;
use std::io::prelude::*;
use std::str;

use rust_bpf::common::instruction::*;

const INSTR_REGEX: &str = r"(\w+:)?\s*([^,\s]+)\s*([^,]+),?\s*([^,]+)?,?\s*([^,]+)?";

#[derive(Clone, Copy, Debug, Default)]
struct AsmInstr<'a> {
  pub lbl: Option<&'a str>,
  pub op: Option<&'a str>,
  pub arg: Option<&'a str>,
  pub lt: Option<&'a str>,
  pub lf: Option<&'a str>,
}

impl<'a> AsmInstr<'a> {
  // XXX: clean this up
  pub fn from_str(src: &str) -> AsmInstr {
    lazy_static! {
      static ref INSTR_RE: Regex = Regex::new(INSTR_REGEX).unwrap();
    }
    let captures = INSTR_RE.captures(src).unwrap();
    let lbl = captures.get(1);
    let op = captures.get(2);
    let arg = captures.get(3);
    let lt = captures.get(4);
    let lf = captures.get(5);
    AsmInstr {
      lbl: match lbl {
        Some(c) => {
          let s = c.as_str();
          let len = s.len();
          Some(&s[..len - 1])
        },
        _ => None,
      },
      op: match op {
        Some(c) => Some(c.as_str()),
        _ => None,
      },
      arg: match arg {
        Some(c) => Some(c.as_str()),
        _ => None,
      },
      lt: match lt {
        Some(c) => Some(c.as_str()),
        _ => None,
      },
      lf: match lf {
        Some(c) => Some(c.as_str()),
        _ => None,
      },
    }
  }
}

///  Addressing mode  Syntax               Description
///
///   0               x/%x                 Register X
///   1               [k]                  BHW at byte offset k in the packet
///   2               [x + k]              BHW at the offset X + k in the packet
///   3               M[k]                 Word at offset k in M[]
///   4               #k                   Literal value stored in k
///   5               4*([k]&0xf)          Lower nibble * 4 at byte offset k in the packet
///   6               L                    Jump label L
///   7               #k,Lt,Lf             Jump to Lt if true, otherwise jump to Lf
///   8               #k,Lt                Jump to Lt if predicate is true
///   9               a/%a                 Accumulator A
#[derive(Clone, Copy, Debug)]
enum AddrMode<'a> {
  Index,
  Packet(u32),
  PacketIndirect(u32),
  ScratchMem(u32),
  Literal(i32),
  PacketNibble(u32),
  JumpLabel(&'a str),
  TwoBranch(&'a str, &'a str),
  OneBranch(&'a str),
  Accumulator,
}

impl<'a> AddrMode<'a> {
  pub fn from_str(s: &str) -> AddrMode {
    lazy_static! {
      static ref MODE_RE_OFFSET: Regex = Regex::new(r"(M)?\[\s*(x\s*\+)?\s*(\d+)\s*\]").unwrap();
      static ref MODE_RE_IMM: Regex = Regex::new(r"#(0x)?(\-?\d+)").unwrap();
    }
    if s == "a" || s == "%a" {
      return AddrMode::Accumulator;
    } else if s == "x" || s == "%x" {
      return AddrMode::Index;
    }

    let offset_caps = MODE_RE_OFFSET.captures(s);
    if offset_caps.is_some() {
      let caps = offset_caps.unwrap();
      let scratch = caps.get(1);
      let idx = caps.get(2);
      let k_str = caps.get(3).unwrap().as_str();
      let k: u32 = k_str.parse().unwrap();
      if scratch.is_some() {
        if idx.is_some() {
          unreachable!()
        }
        return AddrMode::ScratchMem(k);
      } else {
        return match idx {
          Some(_) => AddrMode::PacketIndirect(k),
          _ => AddrMode::Packet(k),
        };
      }
    }

    let imm_caps = MODE_RE_IMM.captures(s);
    if imm_caps.is_some() {
      let caps = imm_caps.unwrap();
      let radix = match caps.get(1) {
        Some(_) => 16,
        _ => 10,
      };
      let k_str = caps.get(2).unwrap().as_str();
      let k = i32::from_str_radix(k_str, radix).unwrap();
      return AddrMode::Literal(k);
    }
    unreachable!()
  }
}

fn main() {
  let mut file = File::open("foo.bar").unwrap();
  let mut prog_str = String::new();
  file.read_to_string(&mut prog_str).unwrap();

  let mut lbl_offsets = HashMap::new();
  let mut prog: Vec<AsmInstr> = Vec::new();
  let mut instructions: Vec<Instruction> = Vec::new();

  for line in prog_str.split_terminator("\n") {
    let instr = AsmInstr::from_str(line);
    if instr.lbl.is_some() {
      lbl_offsets.insert(instr.lbl.unwrap(), prog.len());
    }
    prog.push(instr);
  }

  for instr in prog {
    println!("{:?}", instr);
    let op = instr.op.unwrap();
    let addr_mode = AddrMode::from_str(instr.arg.unwrap());
    println!("{:?}", addr_mode);
  }
}
