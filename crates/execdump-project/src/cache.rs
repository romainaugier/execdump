/*
 * Decompilation cache: the C code of every function with the address of each line, kept on disk so
 * that reopening a binary does not decompile it again.
 *
 * The file is an append-only log of records, the last record of a function wins. Only an index
 * (offset, fingerprint, line count) stays in memory, the texts are read back on demand and the most
 * recently used ones are kept. A record is reused when the fingerprint of the function (build of
 * execdump, annotations of the function and of what it calls) has not changed.
 */

use std::collections::{HashMap, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::Arc;

const MAGIC: &[u8; 4] = b"EDC1";
const HEADER_SIZE: u64 = 33;
const NO_ADDRESS: u64 = u64::MAX;
/// Texts kept in memory
const RECENT: usize = 4096;
/// The log is compacted when opened if most of it is dead records
const COMPACT_MIN_SIZE: u64 = 64 << 20;

/// What the decompiler produced for a function, besides its text
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Meta {
    /// Prototype line of the function
    pub signature: String,
    /// Functions it calls, and the other names it uses (globals, functions taken by address)
    pub calls: Vec<String>,
    pub others: Vec<String>,
    /// Variables: name given by the decompiler, name shown
    pub vars: Vec<(String, String)>,
    /// Prototypes of the functions it uses
    pub decls: Vec<String>,
    /// Globals it uses, with their address
    pub globals: Vec<(String, u64)>,
    /// Annotations that could not be applied
    pub errors: Vec<String>,
}

impl Meta {
    fn encode(&self) -> String {
        let mut out = String::new();
        let mut line = |tag: char, text: &str| {
            out.push(tag);
            out.push(' ');
            out.push_str(&text.replace('\n', " "));
            out.push('\n');
        };

        line('S', &self.signature);
        self.calls.iter().for_each(|c| line('C', c));
        self.others.iter().for_each(|o| line('O', o));
        self.vars.iter().for_each(|(a, b)| line('V', &format!("{}\t{}", a, b)));
        self.decls.iter().for_each(|d| line('D', d));
        self.globals.iter().for_each(|(n, a)| line('G', &format!("{}\t{:x}", n, a)));
        self.errors.iter().for_each(|e| line('E', e));

        return out;
    }

    fn decode(text: &str) -> Meta {
        let mut meta = Meta::default();

        for line in text.lines() {
            let (tag, value) = line.split_at(line.len().min(2));
            let value = value.to_string();

            match tag {
                "S " => meta.signature = value,
                "C " => meta.calls.push(value),
                "O " => meta.others.push(value),
                "V " => {
                    let (a, b) = value.split_once('\t').unwrap_or((&value, &value));
                    meta.vars.push((a.to_string(), b.to_string()));
                }
                "D " => meta.decls.push(value),
                "G " => {
                    if let Some((name, addr)) = value.split_once('\t').and_then(|(n, a)| u64::from_str_radix(a, 16).ok().map(|a| (n, a))) {
                        meta.globals.push((name.to_string(), addr));
                    }
                }
                "E " => meta.errors.push(value),
                _ => {}
            }
        }

        return meta;
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Rendered {
    /// False when the decompilation failed (the text is the error)
    pub ok: bool,
    pub text: String,
    /// Address of each line of the text
    pub lines: Vec<Option<u64>>,
    pub meta: Meta,
}

impl Rendered {
    pub fn line_count(&self) -> usize {
        return self.text.lines().count().max(1);
    }
}

#[derive(Clone, Copy, Debug)]
struct Entry {
    offset: u64,
    /// Size of the record, header included
    size: u64,
    fingerprint: u64,
    lines: u32,
    ok: bool,
}

pub struct Cache {
    file: Option<File>,
    size: u64,
    live: u64,
    index: HashMap<u64, Entry>,
    /// Memory only caches keep every text here
    recent: HashMap<u64, (u64, Arc<Rendered>)>,
    order: VecDeque<u64>,
}

impl Cache {
    /// Cache kept in memory only
    pub fn memory() -> Self {
        return Cache { file: None, size: 0, live: 0, index: HashMap::new(), recent: HashMap::new(), order: VecDeque::new() };
    }

    /// Cache backed by a log file in a directory, created when missing
    pub fn open(dir: &Path) -> io::Result<Self> {
        std::fs::create_dir_all(dir)?;

        let path = dir.join("functions.log");
        let mut cache = Cache::open_file(&path)?;

        if cache.size > COMPACT_MIN_SIZE && cache.live * 2 < cache.size {
            cache.compact(&path)?;
        }

        return Ok(cache);
    }

    fn open_file(path: &Path) -> io::Result<Self> {
        let mut file = OpenOptions::new().read(true).write(true).create(true).truncate(false).open(path)?;
        let size = file.metadata()?.len();
        let mut index: HashMap<u64, Entry> = HashMap::new();
        let mut offset = 0;

        // Only the headers are read, a torn record at the end (crash) is dropped
        while offset + HEADER_SIZE <= size {
            let header = read_header(&mut file, offset)?;

            let Some((addr, entry, payload)) = header else {
                break;
            };

            let next = offset + HEADER_SIZE + payload;

            if next > size {
                break;
            }

            index.insert(addr, Entry { offset, size: next - offset, ..entry });
            offset = next;
        }

        if offset < size {
            file.set_len(offset)?;
        }

        let live = index.values().map(|e| e.size).sum();

        return Ok(Cache { file: Some(file), size: offset, live, index, recent: HashMap::new(), order: VecDeque::new() });
    }

    /// Rewrites the log with the live records only
    fn compact(&mut self, path: &Path) -> io::Result<()> {
        let temporary = path.with_extension("log.new");
        let mut fresh = Cache { file: Some(File::create(&temporary)?), ..Cache::memory() };
        let mut addrs: Vec<u64> = self.index.keys().copied().collect();
        addrs.sort();

        for addr in addrs {
            let fingerprint = self.index[&addr].fingerprint;

            if let Some(rendered) = self.read(addr)? {
                fresh.put(addr, fingerprint, (*rendered).clone());
            }
        }

        drop(fresh);
        std::fs::rename(&temporary, path)?;
        *self = Cache::open_file(path)?;

        return Ok(());
    }

    pub fn len(&self) -> usize {
        return self.index.len().max(self.recent.len());
    }

    pub fn fingerprint(&self, addr: u64) -> Option<u64> {
        return self.index.get(&addr).map(|e| e.fingerprint).or_else(|| self.recent.get(&addr).map(|(f, _)| *f));
    }

    /// Number of lines of the text of a function, without reading it
    pub fn line_count(&self, addr: u64) -> Option<usize> {
        return self.index.get(&addr).map(|e| e.lines as usize).or_else(|| self.recent.get(&addr).map(|(_, r)| r.line_count()));
    }

    /// Latest text of a function and the fingerprint it was made with
    pub fn latest(&mut self, addr: u64) -> Option<(u64, Arc<Rendered>)> {
        if let Some((fingerprint, rendered)) = self.recent.get(&addr) {
            return Some((*fingerprint, rendered.clone()));
        }

        let fingerprint = self.index.get(&addr)?.fingerprint;
        let rendered = self.read(addr).ok().flatten()?;
        self.remember(addr, fingerprint, rendered.clone());

        return Some((fingerprint, rendered));
    }

    /// Text of a function, if it was made with this fingerprint
    pub fn get(&mut self, addr: u64, fingerprint: u64) -> Option<Arc<Rendered>> {
        if self.fingerprint(addr) != Some(fingerprint) {
            return None;
        }

        return self.latest(addr).map(|(_, r)| r);
    }

    pub fn put(&mut self, addr: u64, fingerprint: u64, rendered: Rendered) -> Arc<Rendered> {
        let rendered = Arc::new(rendered);

        if let Some(file) = self.file.as_mut() {
            let meta = rendered.meta.encode();
            let mut record = Vec::with_capacity(HEADER_SIZE as usize + rendered.text.len() + rendered.lines.len() * 8 + meta.len());

            record.extend_from_slice(MAGIC);
            record.extend_from_slice(&addr.to_le_bytes());
            record.extend_from_slice(&fingerprint.to_le_bytes());
            record.push(rendered.ok as u8);
            record.extend_from_slice(&(rendered.lines.len() as u32).to_le_bytes());
            record.extend_from_slice(&(rendered.text.len() as u32).to_le_bytes());
            record.extend_from_slice(&(meta.len() as u32).to_le_bytes());
            record.extend_from_slice(rendered.text.as_bytes());

            for line in rendered.lines.iter() {
                record.extend_from_slice(&line.unwrap_or(NO_ADDRESS).to_le_bytes());
            }

            record.extend_from_slice(meta.as_bytes());

            let written = file.seek(SeekFrom::Start(self.size)).and_then(|_| file.write_all(&record));

            if written.is_ok() {
                if let Some(old) = self.index.get(&addr) {
                    self.live = self.live.saturating_sub(old.size);
                }

                let entry = Entry { offset: self.size, size: record.len() as u64, fingerprint, lines: rendered.line_count() as u32, ok: rendered.ok };
                self.index.insert(addr, entry);
                self.size += record.len() as u64;
                self.live += record.len() as u64;
            }
        }

        self.remember(addr, fingerprint, rendered.clone());
        return rendered;
    }

    fn remember(&mut self, addr: u64, fingerprint: u64, rendered: Arc<Rendered>) {
        if self.recent.insert(addr, (fingerprint, rendered)).is_none() {
            self.order.push_back(addr);
        }

        // Memory only caches keep everything: there is nowhere to read them back from
        while self.file.is_some() && self.recent.len() > RECENT {
            if let Some(old) = self.order.pop_front() {
                self.recent.remove(&old);
            }
        }
    }

    fn read(&mut self, addr: u64) -> io::Result<Option<Arc<Rendered>>> {
        let (Some(file), Some(entry)) = (self.file.as_mut(), self.index.get(&addr).copied()) else {
            return Ok(None);
        };

        file.seek(SeekFrom::Start(entry.offset + 21))?;

        let mut sizes = [0u8; 12];
        file.read_exact(&mut sizes)?;
        let count = u32::from_le_bytes(sizes[0..4].try_into().unwrap()) as usize;
        let text_len = u32::from_le_bytes(sizes[4..8].try_into().unwrap()) as usize;
        let meta_len = u32::from_le_bytes(sizes[8..12].try_into().unwrap()) as usize;

        let mut payload = vec![0u8; text_len + count * 8 + meta_len];
        file.read_exact(&mut payload)?;

        let text = String::from_utf8_lossy(&payload[..text_len]).into_owned();
        let lines = payload[text_len..text_len + count * 8]
            .chunks_exact(8)
            .map(|c| u64::from_le_bytes(c.try_into().unwrap()))
            .map(|a| if a == NO_ADDRESS { None } else { Some(a) })
            .collect();
        let meta = Meta::decode(&String::from_utf8_lossy(&payload[text_len + count * 8..]));

        return Ok(Some(Arc::new(Rendered { ok: entry.ok, text, lines, meta })));
    }
}

/// Address, entry (without its offset) and payload size of the record at an offset
fn read_header(file: &mut File, offset: u64) -> io::Result<Option<(u64, Entry, u64)>> {
    let mut header = [0u8; HEADER_SIZE as usize];
    file.seek(SeekFrom::Start(offset))?;

    if file.read_exact(&mut header).is_err() || &header[0..4] != MAGIC {
        return Ok(None);
    }

    let u32_at = |i: usize| u32::from_le_bytes(header[i..i + 4].try_into().unwrap());
    let addr = u64::from_le_bytes(header[4..12].try_into().unwrap());
    let fingerprint = u64::from_le_bytes(header[12..20].try_into().unwrap());
    let ok = header[20] != 0;
    let (count, text_len, meta_len) = (u32_at(21), u32_at(25), u32_at(29));

    let entry = Entry { offset, size: 0, fingerprint, lines: 0, ok };
    let payload = text_len as u64 + count as u64 * 8 + meta_len as u64;

    // The line count is the number of text lines, stored with the line addresses
    return Ok(Some((addr, Entry { lines: count.max(1), ..entry }, payload)));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rendered(text: &str) -> Rendered {
        let lines = text.lines().enumerate().map(|(i, _)| if i % 2 == 0 { Some(0x1000 + i as u64) } else { None }).collect();
        let meta = Meta {
            signature: "int f(void)".to_string(),
            calls: vec!["g".to_string()],
            vars: vec![("v1".to_string(), "count".to_string())],
            globals: vec![("g_4000".to_string(), 0x4000)],
            ..Meta::default()
        };

        return Rendered { ok: true, text: text.to_string(), lines, meta };
    }

    #[test]
    fn records_survive_reopening() {
        let dir = std::env::temp_dir().join(format!("execdump-cache-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        {
            let mut cache = Cache::open(&dir).unwrap();
            cache.put(0x1000, 1, rendered("int f(void)\n{\n}\n"));
            cache.put(0x2000, 7, rendered("int g(void)\n{\n    return 0;\n}\n"));
            cache.put(0x1000, 2, rendered("int f(void)\n{\n    g();\n}\n"));
        }

        // A torn record at the end is dropped
        OpenOptions::new().append(true).open(dir.join("functions.log")).unwrap().write_all(b"EDC1\x01\x02").unwrap();

        let mut cache = Cache::open(&dir).unwrap();
        assert_eq!(cache.fingerprint(0x1000), Some(2));
        assert_eq!(cache.line_count(0x2000), Some(4));
        assert!(cache.get(0x1000, 1).is_none());

        let f = cache.get(0x1000, 2).unwrap();
        assert_eq!(f.text, "int f(void)\n{\n    g();\n}\n");
        assert_eq!(f.lines, vec![Some(0x1000), None, Some(0x1002), None]);
        assert_eq!(f.meta.vars, vec![("v1".to_string(), "count".to_string())]);
        assert_eq!(f.meta.calls, vec!["g".to_string()]);
        assert_eq!(f.meta.globals, vec![("g_4000".to_string(), 0x4000)]);

        cache.put(0x3000, 3, rendered("x\n"));
        drop(cache);
        assert_eq!(Cache::open(&dir).unwrap().fingerprint(0x3000), Some(3));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn memory() {
        let mut cache = Cache::memory();
        cache.put(1, 5, rendered("a\nb\n"));
        assert_eq!(cache.get(1, 5).unwrap().text, "a\nb\n");
        assert_eq!(cache.line_count(1), Some(2));
    }
}
