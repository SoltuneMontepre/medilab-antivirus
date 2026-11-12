//! Deterministic file tree for scan benchmarks (issue #9's `scripts/gen-tree`):
//! `cargo run --release -p daemon --example gen_tree -- <dir> [count]`, default 10000 files.
//! Nested dirs, sizes 0 B to 4 MiB, PE/ELF/script/PDF/ZIP/OLE magic headers over random bytes,
//! and every 100th file a real small (stored) ZIP with a nested ZIP inside.

use std::path::PathBuf;

/// xorshift64: fixed seed, so every run writes the same tree.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> usize {
        (self.next() % n) as usize
    }
    fn bytes(&mut self, len: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(len + 8);
        while v.len() < len {
            v.extend(self.next().to_le_bytes());
        }
        v.truncate(len);
        v
    }
}

const TYPES: [(&[u8], &str); 7] = [
    (b"MZ\x90\x00", "exe"),
    (b"\x7fELF\x02\x01\x01", "elf"),
    (b"#!/bin/sh\n", "sh"),
    (b"%PDF-1.7\n", "pdf"),
    (b"PK\x03\x04", "zip"),
    (b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", "doc"),
    (b"", "bin"),
];

fn crc32(data: &[u8]) -> u32 {
    let mut c = !0u32;
    for &b in data {
        c ^= b as u32;
        for _ in 0..8 {
            c = (c >> 1) ^ (0xEDB8_8320 & (c & 1).wrapping_neg());
        }
    }
    !c
}

/// Minimal valid ZIP with stored (uncompressed) entries.
fn stored_zip(entries: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let (mut out, mut cd) = (Vec::new(), Vec::new());
    for (name, body) in entries {
        let len = body.len() as u32;
        // flags, method (stored), time, date (1980-01-01), crc, sizes, name length, extra length
        let mut fields = Vec::new();
        for x in [0u16, 0, 0, 0x21] {
            fields.extend(x.to_le_bytes());
        }
        for x in [crc32(body), len, len] {
            fields.extend(x.to_le_bytes());
        }
        fields.extend((name.len() as u16).to_le_bytes());
        fields.extend(0u16.to_le_bytes());
        let offset = out.len() as u32;
        out.extend(b"PK\x03\x04\x14\x00");
        out.extend(&fields);
        out.extend(name.as_bytes());
        out.extend(body);
        cd.extend(b"PK\x01\x02\x14\x00\x14\x00");
        cd.extend(&fields);
        cd.extend([0u8; 10]); // comment length, disk, internal and external attributes
        cd.extend(offset.to_le_bytes());
        cd.extend(name.as_bytes());
    }
    let (cd_offset, n) = (out.len() as u32, entries.len() as u16);
    out.extend(&cd);
    out.extend(b"PK\x05\x06\0\0\0\0");
    out.extend(n.to_le_bytes());
    out.extend(n.to_le_bytes());
    out.extend((cd.len() as u32).to_le_bytes());
    out.extend(cd_offset.to_le_bytes());
    out.extend(0u16.to_le_bytes());
    out
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(root) = args.first().map(PathBuf::from) else {
        eprintln!("usage: gen_tree <dir> [count]");
        std::process::exit(2);
    };
    let count: usize = args.get(1).map_or(10_000, |c| c.parse().expect("count must be a number"));
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let mut total = 0u64;
    for i in 0..count {
        let mut dir = root.clone();
        for _ in 0..rng.below(5) {
            dir.push(format!("d{}", rng.below(6)));
        }
        std::fs::create_dir_all(&dir).unwrap();
        let (data, ext) = if i % 100 == 0 {
            let (a, b) = (rng.below(4096), rng.below(8192));
            let inner = stored_zip(&[("inner.txt", rng.bytes(a))]);
            (stored_zip(&[("a.bin", rng.bytes(b)), ("b/inner.zip", inner)]), "zip")
        } else {
            // Mostly small, a long tail up to 4 MiB.
            let size = match rng.below(100) {
                0..60 => rng.below(4 << 10),
                60..90 => (4 << 10) + rng.below(60 << 10),
                90..99 => (64 << 10) + rng.below(448 << 10),
                _ => (512 << 10) + rng.below(3584 << 10),
            };
            let (magic, ext) = TYPES[rng.below(TYPES.len() as u64)];
            let mut data = magic.to_vec();
            data.extend(rng.bytes(size));
            data.truncate(size); // size 0 stays an empty file
            (data, ext)
        };
        total += data.len() as u64;
        std::fs::write(dir.join(format!("f{i:05}.{ext}")), data).unwrap();
    }
    println!("{count} files, {total} bytes under {}", root.display());
}
