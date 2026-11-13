//! Archive and container extraction (ZIP/JAR/APK/OOXML, TAR/GZ, 7z, ISO) with bomb limits.

use std::io::{Cursor, Read};

use serde::{Deserialize, Serialize};

/// The ratio check only kicks in past this many decompressed bytes, so tiny entries never trip it.
const RATIO_FLOOR: u64 = 1 << 20;
/// Per-decoder dictionary limit for 7z. 7-Zip's -mx9 uses 64 MiB; a header can claim GiBs.
const SEVENZ_MEM_LIMIT_KB: usize = 256 * 1024;
/// ISO directory nesting cap (ISO 9660 itself allows 8 levels).
const ISO_MAX_DEPTH: u32 = 32;

/// `[archives]`: archive bomb limits, all per top-level file.
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(default)]
pub struct Limits {
    /// Containers at depth < `max_depth` are opened (outer file = depth 0).
    pub max_depth: u32,
    pub max_entries: u64,
    /// Decompressed bytes across all nesting levels.
    pub max_total_bytes: u64,
    /// Per-entry decompressed/compressed ratio above which the entry is treated as a bomb.
    /// Real files rarely beat ~20:1; only long runs of identical bytes approach deflate's ~1000:1 max.
    pub max_ratio: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self { max_depth: 5, max_entries: 10_000, max_total_bytes: 1 << 30, max_ratio: 100 }
    }
}

/// Remaining allowance and tallies for one outer file, shared across all nesting levels.
pub struct Budget {
    pub entries: u64,
    pub bytes: u64,
    max_ratio: u64,
    /// Encrypted entries (7z: blocks) skipped.
    pub encrypted: u64,
    /// Set by the first limit hit; after that no further entry is read from this outer file.
    pub limit_hit: bool,
}

impl Budget {
    pub fn new(limits: &Limits) -> Self {
        Self {
            entries: limits.max_entries,
            bytes: limits.max_total_bytes,
            max_ratio: limits.max_ratio,
            encrypted: 0,
            limit_hit: false,
        }
    }

    fn hit(&mut self, why: String) -> Result<Option<Vec<u8>>, String> {
        self.limit_hit = true;
        Err(why)
    }
}

/// True if `data` looks like a container we can open.
pub fn is_container(data: &[u8]) -> bool {
    data.starts_with(b"PK\x03\x04")
        || data.starts_with(&[0x1f, 0x8b])
        || data.get(257..262) == Some(b"ustar")
        || data.starts_with(&[0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c])
        || data.get(0x8001..0x8006) == Some(b"CD001")
}

/// Calls `visit(entry_name, entry_bytes, budget)` for each regular-file entry, one level only.
pub fn for_each_entry(
    data: &[u8],
    max_entry_size: u64,
    budget: &mut Budget,
    visit: &mut dyn FnMut(&str, &[u8], &mut Budget),
) -> Result<(), String> {
    if data.starts_with(b"PK\x03\x04") {
        zip(data, max_entry_size, budget, visit)
    } else if data.starts_with(&[0x1f, 0x8b]) {
        gzip(data, max_entry_size, budget, visit)
    } else if data.get(257..262) == Some(b"ustar") {
        tar(data, max_entry_size, budget, visit)
    } else if data.starts_with(&[0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]) {
        sevenz(data, max_entry_size, budget, visit)
    } else if data.get(0x8001..0x8006) == Some(b"CD001") {
        iso(data, max_entry_size, budget, visit)
    } else {
        Err("not a supported container".into())
    }
}

/// Reads one entry under the size cap, ratio check and budget.
/// `Ok(None)` means the entry was over `max_entry_size` and skipped.
/// A limit hit sets `budget.limit_hit` and returns `Err`.
fn read_entry(
    r: &mut dyn Read,
    name: &str,
    packed: u64,
    max_entry_size: u64,
    budget: &mut Budget,
) -> Result<Option<Vec<u8>>, String> {
    if budget.limit_hit {
        return Err(format!("{name}: not read, an archive limit was already hit"));
    }
    if budget.entries == 0 {
        return budget.hit(format!("archive budget exhausted (entry count) at {name}"));
    }
    budget.entries -= 1;
    let limit = max_entry_size.min(budget.bytes);
    let mut r = r.take(limit.saturating_add(1)); // never trust header sizes
    let mut out = Vec::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = r.read(&mut buf).map_err(|e| format!("{name}: {e}"))?;
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n]);
        let len = out.len() as u64;
        if len > RATIO_FLOOR && len / packed.max(1) > budget.max_ratio {
            let ratio = budget.max_ratio;
            return budget.hit(format!("{name}: compression ratio over {ratio}:1, likely archive bomb"));
        }
    }
    let len = out.len() as u64;
    budget.bytes = budget.bytes.saturating_sub(len);
    if len > max_entry_size {
        log::warn!("{name}: entry larger than {max_entry_size} bytes, skipped");
        return Ok(None);
    }
    if len > limit {
        return budget.hit(format!("archive budget exhausted (decompressed bytes) at {name}"));
    }
    Ok(Some(out))
}

fn zip(
    data: &[u8],
    max: u64,
    budget: &mut Budget,
    visit: &mut dyn FnMut(&str, &[u8], &mut Budget),
) -> Result<(), String> {
    let mut archive = zip::ZipArchive::new(Cursor::new(data)).map_err(|e| format!("zip: {e}"))?;
    for i in 0..archive.len() {
        let meta = archive.by_index_data(i).map_err(|e| format!("zip: {e}"))?;
        let name = match meta.name() {
            Ok(n) => n.replace('\\', "/"),
            Err(_) => String::from_utf8_lossy(meta.name_raw()).replace('\\', "/"),
        };
        if !meta.is_file() {
            continue;
        }
        if meta.encrypted() {
            log::debug!("zip: {name}: encrypted, skipped");
            budget.encrypted += 1;
            continue;
        }
        let packed = meta.compressed_size();
        let mut file = match archive.by_index(i) {
            Ok(f) => f,
            Err(zip::result::ZipError::UnsupportedArchive(why)) => {
                log::debug!("zip: {name}: {why}, skipped");
                continue;
            }
            Err(e) => return Err(format!("zip: {name}: {e}")),
        };
        if let Some(bytes) = read_entry(&mut file, &name, packed, max, budget)? {
            visit(&name, &bytes, budget);
        }
    }
    Ok(())
}

fn gzip(
    data: &[u8],
    max: u64,
    budget: &mut Budget,
    visit: &mut dyn FnMut(&str, &[u8], &mut Budget),
) -> Result<(), String> {
    let mut gz = flate2::read::MultiGzDecoder::new(data);
    let bytes = read_entry(&mut gz, "gzip", data.len() as u64, max, budget)?;
    let name = gz
        .header()
        .and_then(|h| h.filename())
        .map(|n| String::from_utf8_lossy(n).replace('\\', "/"))
        .unwrap_or_else(|| "data".into());
    if let Some(bytes) = bytes {
        visit(&name, &bytes, budget);
    }
    Ok(())
}

fn tar(
    data: &[u8],
    max: u64,
    budget: &mut Budget,
    visit: &mut dyn FnMut(&str, &[u8], &mut Budget),
) -> Result<(), String> {
    let mut archive = tar::Archive::new(data);
    for entry in archive.entries().map_err(|e| format!("tar: {e}"))? {
        let mut entry = entry.map_err(|e| format!("tar: {e}"))?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let name = String::from_utf8_lossy(&entry.path_bytes()).replace('\\', "/");
        // packed = whole archive: stored entries never trip the ratio, sparse-file bombs do.
        if let Some(bytes) = read_entry(&mut entry, &name, data.len() as u64, max, budget)? {
            visit(&name, &bytes, budget);
        }
    }
    Ok(())
}

fn sevenz(
    data: &[u8],
    max: u64,
    budget: &mut Budget,
    visit: &mut dyn FnMut(&str, &[u8], &mut Budget),
) -> Result<(), String> {
    use sevenz_rust2::{Archive, BlockDecoder, Password};
    let mut src = Cursor::new(data);
    let password = Password::empty();
    let archive = match Archive::read_with_memory_limit(&mut src, &password, SEVENZ_MEM_LIMIT_KB) {
        Ok(a) => a,
        // Encrypted header: there is nothing to list without the password.
        Err(sevenz_rust2::Error::PasswordRequired) => {
            budget.encrypted += 1;
            return Ok(());
        }
        Err(e @ sevenz_rust2::Error::MaxMemLimited { .. }) => {
            budget.limit_hit = true;
            return Err(format!("7z: {e}"));
        }
        Err(e) => return Err(format!("7z: {e}")),
    };
    let mut failure = None;
    for block in 0..archive.blocks.len() {
        let first = archive.stream_map.block_first_file_index.get(block).copied().unwrap_or(usize::MAX);
        if archive.is_file_encrypted(first) {
            log::debug!("7z: block {block} encrypted, skipped");
            budget.encrypted += 1;
            continue;
        }
        let decoder = BlockDecoder::new_with_memory_limit(1, SEVENZ_MEM_LIMIT_KB, block, &archive, &password, &mut src);
        decoder
            .for_each_entries(&mut |entry, r| {
                if entry.is_directory() || !entry.has_stream() {
                    return Ok(true);
                }
                let name = entry.name().replace('\\', "/");
                // ponytail: ratio uses the whole archive as `packed` (solid blocks have no per-entry size);
                // lenient for multi-entry archives, the size cap and budget still bound the work.
                match read_entry(r, &name, data.len() as u64, max, budget) {
                    Ok(Some(bytes)) => {
                        visit(&name, &bytes, budget);
                        Ok(true)
                    }
                    // Over cap: skip the rest of the block rather than decode through a possible bomb.
                    Ok(None) => Ok(false),
                    Err(e) => {
                        failure = Some(e);
                        Ok(false)
                    }
                }
            })
            .map_err(|e| format!("7z: {e}"))?;
        if let Some(e) = failure {
            return Err(e);
        }
    }
    Ok(())
}

fn iso(
    data: &[u8],
    max: u64,
    budget: &mut Budget,
    visit: &mut dyn FnMut(&str, &[u8], &mut Budget),
) -> Result<(), String> {
    const PVD: usize = 16 * 2048;
    let u16le = |at: usize| data.get(at..at + 2).map(|b| u16::from_le_bytes([b[0], b[1]]) as u64);
    let u32le = |rec: &[u8], at: usize| u32::from_le_bytes([rec[at], rec[at + 1], rec[at + 2], rec[at + 3]]) as u64;
    if data.get(PVD) != Some(&1) {
        return Err("iso: no primary volume descriptor at sector 16".into());
    }
    let block = u16le(PVD + 128).filter(|&b| b != 0).ok_or("iso: bad logical block size")?;
    let root = data.get(PVD + 156..PVD + 156 + 34).ok_or("iso: truncated root record")?;
    // Directory extents of a real image never overlap, so their total cannot exceed the image;
    // this bounds the walk linearly even for looping or overlapping directory records.
    let mut dir_bytes = 0u64;
    let mut stack = vec![(u32le(root, 2), u32le(root, 10), String::new(), 0u32)];
    while let Some((lba, size, prefix, depth)) = stack.pop() {
        if depth > ISO_MAX_DEPTH {
            return Err("iso: directory nesting too deep".into());
        }
        dir_bytes += size;
        if dir_bytes > data.len() as u64 {
            return Err("iso: directory tree larger than the image".into());
        }
        let start = lba * block;
        let dir = data.get(start as usize..(start + size) as usize).ok_or("iso: directory extent out of bounds")?;
        let mut off = 0usize;
        while off < dir.len() {
            let len = dir[off] as usize;
            if len == 0 {
                // Records never cross a sector; zero padding runs to the next one.
                off = (off as u64 / block + 1) as usize * block as usize;
                continue;
            }
            let rec = dir.get(off..off + len).filter(|r| r.len() >= 34).ok_or("iso: malformed directory record")?;
            off += len;
            let name_len = rec[32] as usize;
            let raw = rec.get(33..33 + name_len).ok_or("iso: malformed directory record")?;
            if raw == [0] || raw == [1] {
                continue; // self / parent
            }
            let raw = String::from_utf8_lossy(raw);
            let name = raw.split(';').next().unwrap_or_default().trim_end_matches('.');
            let path = format!("{prefix}{name}");
            let (ext_lba, ext_len) = (u32le(rec, 2), u32le(rec, 10));
            if rec[25] & 2 != 0 {
                stack.push((ext_lba, ext_len, format!("{path}/"), depth + 1));
                continue;
            }
            let at = ext_lba * block;
            let mut bytes = data.get(at as usize..(at + ext_len) as usize).ok_or("iso: file extent out of bounds")?;
            if let Some(bytes) = read_entry(&mut bytes, &path, data.len() as u64, max, budget)? {
                visit(&path, &bytes, budget);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::Write;

    const PAYLOAD: &[u8] = b"hello payload";

    fn new_budget() -> Budget {
        Budget::new(&Limits::default())
    }

    fn collect(data: &[u8]) -> Result<Vec<(String, Vec<u8>)>, String> {
        let mut out = Vec::new();
        for_each_entry(data, 64 << 20, &mut new_budget(), &mut |n, b, _| out.push((n.to_string(), b.to_vec())))?;
        Ok(out)
    }

    pub(crate) fn make_zip(name: &str, body: &[u8]) -> Vec<u8> {
        let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
        w.add_directory("dir/", zip::write::SimpleFileOptions::default()).unwrap();
        w.start_file(name, zip::write::SimpleFileOptions::default()).unwrap();
        w.write_all(body).unwrap();
        w.finish().unwrap().into_inner()
    }

    pub(crate) fn make_tar(name: &str, body: &[u8]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_ustar();
        h.set_size(body.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, name, body).unwrap();
        b.into_inner().unwrap()
    }

    pub(crate) fn make_gz(name: Option<&str>, body: &[u8]) -> Vec<u8> {
        let mut builder = flate2::GzBuilder::new();
        if let Some(n) = name {
            builder = builder.filename(n);
        }
        let mut w = builder.write(Vec::new(), flate2::Compression::default());
        w.write_all(body).unwrap();
        w.finish().unwrap()
    }

    pub(crate) fn make_7z(name: &str, body: &[u8]) -> Vec<u8> {
        let mut w = sevenz_rust2::ArchiveWriter::new(Cursor::new(Vec::new())).unwrap();
        w.push_archive_entry(sevenz_rust2::ArchiveEntry::new_file(name), Some(body)).unwrap();
        w.finish().unwrap().into_inner()
    }

    /// ISO image holding `SUB/<name>`. Sectors: 16 = PVD, 18 = root dir, 19 = subdir "SUB", 20.. = file data.
    pub(crate) fn make_iso(name: &[u8], body: &[u8]) -> Vec<u8> {
        fn record(lba: u32, len: u32, dir: bool, name: &[u8]) -> Vec<u8> {
            let mut r = vec![0u8; 33];
            r[2..6].copy_from_slice(&lba.to_le_bytes());
            r[10..14].copy_from_slice(&len.to_le_bytes());
            r[25] = if dir { 2 } else { 0 };
            r[32] = name.len() as u8;
            r.extend_from_slice(name);
            if r.len() % 2 == 1 {
                r.push(0);
            }
            r[0] = r.len() as u8;
            r
        }
        let mut img = vec![0u8; 20 * 2048 + body.len()];
        img[0x8000] = 1;
        img[0x8001..0x8006].copy_from_slice(b"CD001");
        img[0x8000 + 128..0x8000 + 130].copy_from_slice(&2048u16.to_le_bytes());
        let root = record(18, 2048, true, &[0]);
        img[0x8000 + 156..0x8000 + 156 + root.len()].copy_from_slice(&root);
        let root_dir =
            [record(18, 2048, true, &[0]), record(18, 2048, true, &[1]), record(19, 2048, true, b"SUB")].concat();
        img[18 * 2048..18 * 2048 + root_dir.len()].copy_from_slice(&root_dir);
        let sub_dir =
            [record(19, 2048, true, &[0]), record(18, 2048, true, &[1]), record(20, body.len() as u32, false, name)]
                .concat();
        img[19 * 2048..19 * 2048 + sub_dir.len()].copy_from_slice(&sub_dir);
        img[20 * 2048..].copy_from_slice(body);
        img
    }

    #[test]
    fn zip_entry() {
        let z = make_zip("dir/a.txt", PAYLOAD);
        assert!(is_container(&z));
        assert_eq!(collect(&z).unwrap(), vec![("dir/a.txt".into(), PAYLOAD.to_vec())]);
    }

    #[test]
    fn tar_entry() {
        let t = make_tar("x/y.bin", PAYLOAD);
        assert!(is_container(&t));
        assert_eq!(collect(&t).unwrap(), vec![("x/y.bin".into(), PAYLOAD.to_vec())]);
    }

    #[test]
    fn gzip_entry() {
        assert_eq!(collect(&make_gz(Some("p.txt"), PAYLOAD)).unwrap(), vec![("p.txt".into(), PAYLOAD.to_vec())]);
        assert_eq!(collect(&make_gz(None, PAYLOAD)).unwrap(), vec![("data".into(), PAYLOAD.to_vec())]);
    }

    #[test]
    fn sevenz_entry() {
        let s = make_7z("s/z.txt", PAYLOAD);
        assert!(is_container(&s));
        assert_eq!(collect(&s).unwrap(), vec![("s/z.txt".into(), PAYLOAD.to_vec())]);
    }

    #[test]
    fn iso_entry() {
        let img = make_iso(b"A.TXT;1", PAYLOAD);
        assert!(is_container(&img));
        assert_eq!(collect(&img).unwrap(), vec![("SUB/A.TXT".into(), PAYLOAD.to_vec())]);
    }

    #[test]
    fn nested_zip_tar_gz() {
        let z = make_zip("inner.tar.gz", &make_gz(None, &make_tar("deep/file.txt", PAYLOAD)));
        fn walk(data: &[u8], path: &str, budget: &mut Budget, found: &mut Vec<String>) {
            let mut kids = Vec::new();
            for_each_entry(data, 64 << 20, budget, &mut |n, b, _| kids.push((format!("{path}!{n}"), b.to_vec())))
                .unwrap();
            for (p, b) in kids {
                if is_container(&b) {
                    walk(&b, &p, budget, found);
                } else if b == PAYLOAD {
                    found.push(p);
                }
            }
        }
        let mut found = Vec::new();
        walk(&z, "a.zip", &mut new_budget(), &mut found);
        assert_eq!(found, vec!["a.zip!inner.tar.gz!data!deep/file.txt"]);
    }

    #[test]
    fn zip_bomb_rejected() {
        let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
        w.start_file("zeros", zip::write::SimpleFileOptions::default()).unwrap();
        let mb = vec![0u8; 1 << 20];
        for _ in 0..50 {
            w.write_all(&mb).unwrap();
        }
        let z = w.finish().unwrap().into_inner();
        let mut called = false;
        let err = for_each_entry(&z, 1 << 30, &mut new_budget(), &mut |_, _, _| called = true).unwrap_err();
        assert!(err.contains("ratio"), "{err}");
        assert!(!called);
        // Under a small size cap the same entry is skipped instead (cap hits before the ratio floor).
        for_each_entry(&z, 1000, &mut new_budget(), &mut |_, _, _| called = true).unwrap();
        assert!(!called);
    }

    #[test]
    fn garbage_is_err() {
        let z = make_zip("a.txt", PAYLOAD);
        let mut noise = vec![0u8; 40_000];
        let mut x = 0x1234_5678u32;
        for b in noise.iter_mut() {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            *b = x as u8;
        }
        let mut inputs = vec![z[..z.len() / 2].to_vec(), make_gz(None, PAYLOAD)[..8].to_vec(), noise.clone()];
        for magic in [&b"PK\x03\x04"[..], &[0x1f, 0x8b], &[0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]] {
            let mut d = noise.clone();
            d[..magic.len()].copy_from_slice(magic);
            inputs.push(d);
        }
        let mut iso = noise.clone();
        iso[0x8000] = 1;
        iso[0x8001..0x8006].copy_from_slice(b"CD001");
        inputs.push(iso);
        for d in inputs {
            assert!(for_each_entry(&d, 1 << 20, &mut new_budget(), &mut |_, _, _| {}).is_err());
        }
    }
}
