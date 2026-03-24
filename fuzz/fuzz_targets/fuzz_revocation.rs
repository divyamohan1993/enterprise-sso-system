#![no_main]
use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use common::revocation::RevocationList;
#[derive(Arbitrary, Debug)] enum Op { R([u8;16]), C([u8;16]), Cl, Ce(u16) }
#[derive(Arbitrary, Debug)] struct RI { ops: Vec<Op> }
fuzz_target!(|i: RI| { let mut rl = RevocationList::new(); for op in &i.ops { match op { Op::R(id) => { let _ = rl.revoke(*id); } Op::C(id) => { let _ = rl.is_revoked(id); } Op::Cl => rl.cleanup(), Op::Ce(s) => rl.cleanup_expired(*s as i64), } } });
