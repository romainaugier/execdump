// SPDX-License-Identifier: Apache-2.0
/*
 * The pointers dyld writes in a Mach-O binary and the symbols it exports.
 *
 * Chained fixups (LC_DYLD_CHAINED_FIXUPS, macOS 12 and later, every arm64e binary): each pointer of the data holds,
 * on disk, either its target (a rebase) or the index of an import (a bind) with the distance to the next one of its
 * page, the chains start at the pages listed for each segment. The older binaries list the binds as opcodes
 * (LC_DYLD_INFO), their rebases are already the right pointers on disk. The exports are a trie of their names.
 *
 * https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/fixup-chains.h
 * https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h
 */

/// A segment of the binary, in the order of the load commands
#[derive(Clone, Copy, Debug, Default)]
pub struct Segment {
    pub vmaddr: u64,
    pub vmsize: u64,
    pub fileoff: u64,
    pub filesize: u64,
}

/// A pointer the loader writes: to an address of the binary, or to an imported symbol
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fixup {
    Rebase { addr: u64, target: u64 },
    Bind { addr: u64, symbol: String, addend: i64 },
}

/// Chained fixups pointer formats (dyld_chained_ptr_format)
const PTR_ARM64E: u16 = 1;
const PTR_64: u16 = 2;
const PTR_32: u16 = 3;
const PTR_64_OFFSET: u16 = 6;
const PTR_ARM64E_USERLAND: u16 = 9;
const PTR_ARM64E_USERLAND24: u16 = 12;

const PAGE_START_NONE: u16 = 0xffff;
/// 32-bit formats: the page has several chains, listed from the index after the flag
const PAGE_START_MULTI: u16 = 0x8000;
const PAGE_START_LAST: u16 = 0x8000;

/// Most links followed in a chain (a page of 16 KB holds 4096 pointers of 4 bytes)
const MAX_CHAIN: usize = 1 << 16;

const EXPORT_KIND_MASK: u64 = 0x03;
const EXPORT_KIND_ABSOLUTE: u64 = 0x02;
const EXPORT_REEXPORT: u64 = 0x08;
const EXPORT_STUB_AND_RESOLVER: u64 = 0x10;

fn bytes<const N: usize>(data: &[u8], at: usize) -> Option<[u8; N]> {
    return data.get(at..at.checked_add(N)?)?.try_into().ok();
}

fn u16_at(data: &[u8], at: usize) -> Option<u16> {
    return bytes(data, at).map(u16::from_le_bytes);
}

fn u32_at(data: &[u8], at: usize) -> Option<u32> {
    return bytes(data, at).map(u32::from_le_bytes);
}

fn u64_at(data: &[u8], at: usize) -> Option<u64> {
    return bytes(data, at).map(u64::from_le_bytes);
}

fn uleb(data: &[u8], pos: &mut usize) -> Option<u64> {
    let mut value = 0u64;
    let mut shift = 0;

    loop {
        let byte = *data.get(*pos)?;
        *pos += 1;

        if shift < 64 {
            value |= ((byte & 0x7f) as u64) << shift;
        }

        shift += 7;

        if byte & 0x80 == 0 {
            return Some(value);
        }
    }
}

fn sleb(data: &[u8], pos: &mut usize) -> Option<i64> {
    let mut value = 0i64;
    let mut shift = 0;

    loop {
        let byte = *data.get(*pos)?;
        *pos += 1;

        if shift < 64 {
            value |= ((byte & 0x7f) as i64) << shift;
        }

        shift += 7;

        if byte & 0x80 == 0 {
            if shift < 64 && byte & 0x40 != 0 {
                value |= -1i64 << shift;
            }

            return Some(value);
        }
    }
}

fn c_string(data: &[u8], pos: &mut usize) -> Option<String> {
    let rest = data.get(*pos..)?;
    let end = rest.iter().position(|&b| b == 0)?;
    *pos += end + 1;
    return Some(String::from_utf8_lossy(&rest[..end]).into_owned());
}

fn bits(value: u64, from: u32, count: u32) -> u64 {
    return value >> from & ((1u64 << count) - 1);
}

fn sign_extend(value: u64, count: u32) -> i64 {
    let shift = 64 - count;
    return ((value << shift) as i64) >> shift;
}

/// Address of the Mach-O header: the start of the segment mapping the beginning of the file
pub fn base_address(segments: &[Segment]) -> u64 {
    return segments.iter().find(|s| s.fileoff == 0 && s.filesize > 0).map_or(0, |s| s.vmaddr);
}

fn file_offset(segments: &[Segment], addr: u64) -> Option<usize> {
    let segment = segments.iter().find(|s| addr >= s.vmaddr && addr < s.vmaddr + s.filesize.min(s.vmsize))?;
    return Some((segment.fileoff + addr - segment.vmaddr) as usize);
}

/// The fixups of LC_DYLD_CHAINED_FIXUPS: data is its blob, file the whole binary (the chains are in the pointers)
pub fn chained_fixups(file: &[u8], data: &[u8], segments: &[Segment]) -> Vec<Fixup> {
    let mut fixups = Vec::new();
    let _ = read_chains(file, data, segments, &mut fixups);
    return fixups;
}

fn read_chains(file: &[u8], data: &[u8], segments: &[Segment], fixups: &mut Vec<Fixup>) -> Option<()> {
    let starts_offset = u32_at(data, 4)? as usize;
    let imports_offset = u32_at(data, 8)? as usize;
    let symbols_offset = u32_at(data, 12)? as usize;
    let imports_count = u32_at(data, 16)? as usize;
    let imports_format = u32_at(data, 20)?;
    let symbols_format = u32_at(data, 24)?;

    // Compressed names (zlib) are not read
    if symbols_format != 0 {
        return None;
    }

    let mut imports = Vec::with_capacity(imports_count);

    for i in 0..imports_count {
        let (name_offset, addend) = match imports_format {
            1 => (bits(u32_at(data, imports_offset + 4 * i)? as u64, 9, 23), 0),
            2 => (bits(u32_at(data, imports_offset + 8 * i)? as u64, 9, 23), u32_at(data, imports_offset + 8 * i + 4)? as i32 as i64),
            3 => (bits(u64_at(data, imports_offset + 16 * i)?, 32, 32), u64_at(data, imports_offset + 16 * i + 8)? as i64),
            _ => return None,
        };

        let mut at = symbols_offset + name_offset as usize;
        imports.push((c_string(data, &mut at)?, addend));
    }

    let base = base_address(segments);
    let seg_count = u32_at(data, starts_offset)? as usize;

    for segment in 0..seg_count.min(segments.len()) {
        let seg_info = u32_at(data, starts_offset + 4 + 4 * segment)? as usize;

        if seg_info == 0 {
            continue;
        }

        let start = starts_offset + seg_info;
        let page_size = u16_at(data, start + 4)? as u64;
        let format = u16_at(data, start + 6)?;
        let segment_offset = u64_at(data, start + 8)?;
        let page_count = u16_at(data, start + 20)? as usize;
        let page_start = |i: usize| u16_at(data, start + 22 + 2 * i);

        for page in 0..page_count {
            let first = page_start(page)?;
            let page_addr = base + segment_offset + page as u64 * page_size;

            if first == PAGE_START_NONE {
                continue;
            }

            if format == PTR_32 && first & PAGE_START_MULTI != 0 {
                let mut index = (first & !PAGE_START_MULTI) as usize;

                loop {
                    let chain = page_start(index)?;
                    walk_chain(file, segments, format, base, page_addr + (chain & !PAGE_START_LAST) as u64, &imports, fixups);

                    if chain & PAGE_START_LAST != 0 {
                        break;
                    }

                    index += 1;
                }

                continue;
            }

            walk_chain(file, segments, format, base, page_addr + first as u64, &imports, fixups);
        }
    }

    return Some(());
}

fn walk_chain(file: &[u8], segments: &[Segment], format: u16, base: u64, mut addr: u64, imports: &[(String, i64)], fixups: &mut Vec<Fixup>) {
    let bind = |ordinal: u64, addend: i64| imports.get(ordinal as usize).map(|(name, a)| Fixup::Bind { addr: 0, symbol: name.clone(), addend: a + addend });

    for _ in 0..MAX_CHAIN {
        let Some(offset) = file_offset(segments, addr) else {
            return;
        };

        let (fixup, next, stride) = match format {
            PTR_64 | PTR_64_OFFSET => {
                let Some(raw) = u64_at(file, offset) else {
                    return;
                };

                let fixup = if raw >> 63 == 1 {
                    bind(bits(raw, 0, 24), bits(raw, 24, 8) as i64)
                } else {
                    let target = bits(raw, 0, 36) | bits(raw, 36, 8) << 56;
                    Some(Fixup::Rebase { addr: 0, target: if format == PTR_64_OFFSET { base + target } else { target } })
                };

                (fixup, bits(raw, 51, 12), 4)
            }
            PTR_ARM64E | PTR_ARM64E_USERLAND | PTR_ARM64E_USERLAND24 => {
                let Some(raw) = u64_at(file, offset) else {
                    return;
                };

                let (auth, is_bind) = (raw >> 63 == 1, raw >> 62 & 1 == 1);
                let ordinal_bits = if format == PTR_ARM64E_USERLAND24 { 24 } else { 16 };

                let fixup = match (auth, is_bind) {
                    (false, false) => {
                        let target = bits(raw, 0, 43);
                        let target = if format == PTR_ARM64E { target } else { base + target };
                        Some(Fixup::Rebase { addr: 0, target: target | bits(raw, 43, 8) << 56 })
                    }
                    (false, true) => bind(bits(raw, 0, ordinal_bits), sign_extend(bits(raw, 32, 19), 19)),
                    (true, false) => Some(Fixup::Rebase { addr: 0, target: base + bits(raw, 0, 32) }),
                    (true, true) => bind(bits(raw, 0, ordinal_bits), 0),
                };

                (fixup, bits(raw, 51, 11), 8)
            }
            PTR_32 => {
                let Some(raw) = u32_at(file, offset).map(|v| v as u64) else {
                    return;
                };

                let fixup = if raw >> 31 == 1 { bind(bits(raw, 0, 20), bits(raw, 20, 6) as i64) } else { Some(Fixup::Rebase { addr: 0, target: bits(raw, 0, 26) }) };

                (fixup, bits(raw, 26, 5), 4)
            }
            _ => return,
        };

        match fixup {
            Some(Fixup::Rebase { target, .. }) => fixups.push(Fixup::Rebase { addr, target }),
            Some(Fixup::Bind { symbol, addend, .. }) => fixups.push(Fixup::Bind { addr, symbol, addend }),
            None => {}
        }

        if next == 0 {
            return;
        }

        addr += next * stride;
    }
}

/// The binds of the opcodes of LC_DYLD_INFO (the lazy ones are separated by BIND_OPCODE_DONE)
pub fn bind_opcodes(stream: &[u8], segments: &[Segment], pointer_size: u64, lazy: bool) -> Vec<Fixup> {
    let mut fixups = Vec::new();
    let mut pos = 0;
    let (mut symbol, mut addend, mut addr) = (String::new(), 0i64, 0u64);

    let mut bind = |addr: u64, symbol: &str, addend: i64| {
        if !symbol.is_empty() {
            fixups.push(Fixup::Bind { addr, symbol: symbol.to_string(), addend });
        }
    };

    while let Some(&byte) = stream.get(pos) {
        pos += 1;
        let immediate = (byte & 0x0f) as u64;

        let done = (|| -> Option<bool> {
            match byte & 0xf0 {
                0x00 => return Some(!lazy),
                0x10 | 0x30 => {}
                0x20 => {
                    uleb(stream, &mut pos)?;
                }
                0x40 => symbol = c_string(stream, &mut pos)?,
                0x50 => {}
                0x60 => addend = sleb(stream, &mut pos)?,
                0x70 => {
                    let segment = segments.get(immediate as usize)?;
                    addr = segment.vmaddr.wrapping_add(uleb(stream, &mut pos)?);
                }
                0x80 => addr = addr.wrapping_add(uleb(stream, &mut pos)?),
                0x90 => {
                    bind(addr, &symbol, addend);
                    addr = addr.wrapping_add(pointer_size);
                }
                0xa0 => {
                    bind(addr, &symbol, addend);
                    addr = addr.wrapping_add(pointer_size).wrapping_add(uleb(stream, &mut pos)?);
                }
                0xb0 => {
                    bind(addr, &symbol, addend);
                    addr = addr.wrapping_add(pointer_size * (immediate + 1));
                }
                0xc0 => {
                    let count = uleb(stream, &mut pos)?;
                    let skip = uleb(stream, &mut pos)?;

                    for _ in 0..count.min(MAX_CHAIN as u64) {
                        bind(addr, &symbol, addend);
                        addr = addr.wrapping_add(pointer_size).wrapping_add(skip);
                    }
                }
                // BIND_OPCODE_THREADED (the arm64e binaries before the chained fixups) and the unknown ones
                _ => return None,
            }

            return Some(false);
        })();

        match done {
            Some(false) => {}
            Some(true) | None => break,
        }
    }

    return fixups;
}

/// The exported symbols of a trie and their addresses (the reexports of other libraries left out)
pub fn exports_trie(trie: &[u8], base: u64) -> Vec<(String, u64)> {
    let mut exports = Vec::new();
    let mut work = vec![(0usize, String::new())];
    let mut visited = std::collections::HashSet::new();

    while let Some((node, prefix)) = work.pop() {
        if !visited.insert(node) {
            continue;
        }

        let mut pos = node;

        let Some(terminal_size) = uleb(trie, &mut pos) else {
            continue;
        };

        let children = pos + terminal_size as usize;

        if terminal_size > 0 {
            let flags = uleb(trie, &mut pos).unwrap_or(EXPORT_REEXPORT);

            if flags & EXPORT_REEXPORT == 0 {
                if let Some(address) = uleb(trie, &mut pos) {
                    let absolute = flags & EXPORT_KIND_MASK == EXPORT_KIND_ABSOLUTE;
                    exports.push((prefix.clone(), if absolute { address } else { base.wrapping_add(address) }));
                }

                // The resolver of a stub and resolver export is another function
                if flags & EXPORT_STUB_AND_RESOLVER != 0 {
                    let _ = uleb(trie, &mut pos);
                }
            }
        }

        pos = children;

        let Some(&count) = trie.get(pos) else {
            continue;
        };

        pos += 1;

        for _ in 0..count {
            let (Some(edge), Some(child)) = (c_string(trie, &mut pos), uleb(trie, &mut pos)) else {
                break;
            };

            work.push((child as usize, format!("{}{}", prefix, edge)));
        }
    }

    exports.sort_by_key(|(_, addr)| *addr);
    return exports;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leb128() {
        let mut pos = 0;
        assert_eq!(uleb(&[0xe5, 0x8e, 0x26], &mut pos), Some(624485));
        assert_eq!(pos, 3);

        let mut pos = 0;
        assert_eq!(sleb(&[0xc0, 0xbb, 0x78], &mut pos), Some(-123456));
    }

    #[test]
    fn chains() {
        let segments = [Segment { vmaddr: 0x100000000, vmsize: 0x1000, fileoff: 0, filesize: 0x40 }];
        let imports: Vec<(String, i64)> = ["_a", "_b", "_c"].iter().map(|n| (n.to_string(), 0)).collect();
        let mut file = vec![0u8; 0x40];

        // arm64e: an authenticated rebase (an offset from the header), then a bind with an addend of -4
        file[0x10..0x18].copy_from_slice(&(1u64 << 63 | 1 << 51 | 0x4f0).to_le_bytes());
        file[0x18..0x20].copy_from_slice(&(1u64 << 62 | (-4i64 as u64 & 0x7ffff) << 32 | 2).to_le_bytes());

        // 64-bit offsets: a rebase with its high byte, 8 bytes (2 strides of 4) before a bind
        file[0x20..0x28].copy_from_slice(&(2u64 << 51 | 0x12 << 36 | 0x4f0).to_le_bytes());
        file[0x28..0x30].copy_from_slice(&(1u64 << 63 | 3 << 24 | 1).to_le_bytes());

        let mut fixups = Vec::new();
        walk_chain(&file, &segments, PTR_ARM64E, 0x100000000, 0x100000010, &imports, &mut fixups);
        walk_chain(&file, &segments, PTR_64_OFFSET, 0x100000000, 0x100000020, &imports, &mut fixups);

        assert_eq!(fixups, vec![
            Fixup::Rebase { addr: 0x100000010, target: 0x1000004f0 },
            Fixup::Bind { addr: 0x100000018, symbol: "_c".to_string(), addend: -4 },
            Fixup::Rebase { addr: 0x100000020, target: 0x12000001000004f0 },
            Fixup::Bind { addr: 0x100000028, symbol: "_b".to_string(), addend: 3 },
        ]);
    }

    #[test]
    fn opcodes() {
        let segments = [Segment::default(), Segment { vmaddr: 0x100000000, vmsize: 0x4000, fileoff: 0, filesize: 0x4000 }, Segment { vmaddr: 0x100004000, vmsize: 0x4000, fileoff: 0x4000, filesize: 0x4000 }];

        // ordinal 1, symbol _a, type pointer, segment 2 offset 0x28, bind, bind with a skip of 8, symbol _b, bind 2 times
        // skipping 0
        let mut stream = vec![0x11, 0x40];
        stream.extend_from_slice(b"_a\0");
        stream.extend_from_slice(&[0x51, 0x72, 0x28, 0x90, 0xa0, 0x08, 0x40]);
        stream.extend_from_slice(b"_b\0");
        stream.extend_from_slice(&[0xc0, 0x02, 0x00, 0x00]);

        let binds = bind_opcodes(&stream, &segments, 8, false);
        let found: Vec<(u64, &str)> = binds.iter().map(|f| match f {
            Fixup::Bind { addr, symbol, .. } => (*addr, symbol.as_str()),
            _ => (0, ""),
        }).collect();

        assert_eq!(found, vec![(0x100004028, "_a"), (0x100004030, "_a"), (0x100004040, "_b"), (0x100004048, "_b")]);
    }
}
