/*
 * Minimal .eh_frame parser, only used to recover function boundaries from the FDEs
 * https://refspecs.linuxfoundation.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic/ehframechpt.html
 */

use crate::reader::{Reader, ReaderResult};

use std::collections::HashMap;

const DW_EH_PE_OMIT: u8 = 0xff;

const DW_EH_PE_ABSPTR: u8 = 0x00;
const DW_EH_PE_ULEB128: u8 = 0x01;
const DW_EH_PE_UDATA2: u8 = 0x02;
const DW_EH_PE_UDATA4: u8 = 0x03;
const DW_EH_PE_UDATA8: u8 = 0x04;
const DW_EH_PE_SLEB128: u8 = 0x09;
const DW_EH_PE_SDATA2: u8 = 0x0a;
const DW_EH_PE_SDATA4: u8 = 0x0b;
const DW_EH_PE_SDATA8: u8 = 0x0c;

const DW_EH_PE_PCREL: u8 = 0x10;

/// Frame Description Entry, describes the code range of a function
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fde {
    pub pc_begin: u64,
    pub pc_range: u64,
}

struct EhFrameParser<'a> {
    data: &'a [u8],
    section_address: u64,
    pointer_size: u8,
    big_endian: bool,
    cie_encodings: HashMap<usize, u8>,
}

impl<'a> EhFrameParser<'a> {
    fn reader_at(&self, position: usize) -> ReaderResult<Reader<'a>> {
        let mut reader = if self.big_endian { Reader::new_be(self.data) } else { Reader::new_le(self.data) };
        reader.set_position(position)?;
        return Ok(reader);
    }

    fn read_encoded(&self, reader: &mut Reader, encoding: u8) -> ReaderResult<u64> {
        let field_address = self.section_address.wrapping_add(reader.position() as u64);

        let value = match encoding & 0x0f {
            DW_EH_PE_ABSPTR => if self.pointer_size == 4 { reader.read_u32()? as u64 } else { reader.read_u64()? },
            DW_EH_PE_ULEB128 => reader.read_uleb128()?,
            DW_EH_PE_UDATA2 => reader.read_u16()? as u64,
            DW_EH_PE_UDATA4 => reader.read_u32()? as u64,
            DW_EH_PE_UDATA8 => reader.read_u64()?,
            DW_EH_PE_SLEB128 => reader.read_sleb128()? as u64,
            DW_EH_PE_SDATA2 => reader.read_i16()? as i64 as u64,
            DW_EH_PE_SDATA4 => reader.read_i32()? as i64 as u64,
            DW_EH_PE_SDATA8 => reader.read_i64()? as u64,
            _ => return Ok(0),
        };

        let value = match encoding & 0x70 {
            DW_EH_PE_PCREL => value.wrapping_add(field_address),
            _ => value,
        };

        if self.pointer_size == 4 {
            return Ok(value & 0xffff_ffff);
        }

        return Ok(value);
    }

    /// Parses the CIE at the given offset and returns the FDE pointer encoding
    fn cie_encoding(&mut self, offset: usize) -> ReaderResult<u8> {
        if let Some(&encoding) = self.cie_encodings.get(&offset) {
            return Ok(encoding);
        }

        let mut reader = self.reader_at(offset)?;

        let length = reader.read_u32()?;

        if length == 0xffff_ffff {
            reader.read_u64()?;
        }

        let _cie_id = reader.read_u32()?;
        let version = reader.read_u8()?;

        let mut augmentation = Vec::new();

        loop {
            let c = reader.read_u8()?;

            if c == 0 {
                break;
            }

            augmentation.push(c);
        }

        if augmentation.starts_with(b"eh") {
            self.read_encoded(&mut reader, DW_EH_PE_ABSPTR)?;
        }

        let _code_alignment = reader.read_uleb128()?;
        let _data_alignment = reader.read_sleb128()?;

        if version == 1 {
            reader.read_u8()?;
        } else {
            reader.read_uleb128()?;
        }

        let mut encoding = DW_EH_PE_ABSPTR;

        if augmentation.first() == Some(&b'z') {
            let _augmentation_length = reader.read_uleb128()?;

            for c in augmentation.iter().skip(1) {
                match c {
                    b'R' => encoding = reader.read_u8()?,
                    b'P' => {
                        let personality_encoding = reader.read_u8()?;
                        self.read_encoded(&mut reader, personality_encoding & 0x7f)?;
                    }
                    b'L' => { reader.read_u8()?; }
                    b'S' | b'B' | b'G' => {}
                    _ => break,
                }
            }
        }

        self.cie_encodings.insert(offset, encoding);

        return Ok(encoding);
    }

    fn parse(&mut self) -> Vec<Fde> {
        let mut fdes = Vec::new();
        let mut position = 0usize;

        while position + 4 <= self.data.len() {
            let Ok(entry) = self.parse_entry(position) else {
                break;
            };

            let Some((next, fde)) = entry else {
                break;
            };

            if let Some(fde) = fde {
                fdes.push(fde);
            }

            position = next;
        }

        return fdes;
    }

    /// Returns the position of the next entry and the FDE if the entry is one
    fn parse_entry(&mut self, position: usize) -> ReaderResult<Option<(usize, Option<Fde>)>> {
        let mut reader = self.reader_at(position)?;

        let mut length = reader.read_u32()? as u64;

        if length == 0 {
            return Ok(None);
        }

        if length == 0xffff_ffff {
            length = reader.read_u64()?;
        }

        let content_start = reader.position();
        let end = content_start.saturating_add(length as usize);

        if end > self.data.len() {
            return Ok(None);
        }

        let id_position = reader.position();
        let id = reader.read_u32()? as usize;

        if id == 0 {
            return Ok(Some((end, None)));
        }

        let Some(cie_offset) = id_position.checked_sub(id) else {
            return Ok(Some((end, None)));
        };

        let encoding = self.cie_encoding(cie_offset)?;

        if encoding == DW_EH_PE_OMIT {
            return Ok(Some((end, None)));
        }

        let pc_begin = self.read_encoded(&mut reader, encoding)?;
        let pc_range = self.read_encoded(&mut reader, encoding & 0x0f)?;

        if pc_begin == 0 || pc_range == 0 {
            return Ok(Some((end, None)));
        }

        return Ok(Some((end, Some(Fde { pc_begin, pc_range }))));
    }
}

/// Parses the FDEs of an .eh_frame section mapped at section_address
pub fn parse_eh_frame(data: &[u8], section_address: u64, pointer_size: u8, big_endian: bool) -> Vec<Fde> {
    let mut parser = EhFrameParser {
        data,
        section_address,
        pointer_size,
        big_endian,
        cie_encodings: HashMap::new(),
    };

    return parser.parse();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cie_and_pcrel_fde() {
        let mut data = Vec::new();

        // CIE: length, id 0, version 1, "zR", code align 1, data align -8, ra 16, aug len 1, enc pcrel|sdata4
        let cie = [0u8, 0, 0, 0, 1, b'z', b'R', 0, 1, 0x78, 16, 1, 0x1b, 0, 0, 0];
        data.extend_from_slice(&(cie.len() as u32).to_le_bytes());
        data.extend_from_slice(&cie);

        // FDE: length, CIE pointer, pc_begin (pcrel), pc_range
        let fde_start = data.len();
        let mut fde = Vec::new();
        fde.extend_from_slice(&((fde_start + 4) as u32).to_le_bytes());
        let pc_field = 0x1000u64 + (fde_start + 8) as u64;
        fde.extend_from_slice(&((0x2000i64 - pc_field as i64) as i32).to_le_bytes());
        fde.extend_from_slice(&0x40u32.to_le_bytes());
        fde.extend_from_slice(&[0, 0, 0, 0]);
        data.extend_from_slice(&(fde.len() as u32).to_le_bytes());
        data.extend_from_slice(&fde);

        data.extend_from_slice(&[0, 0, 0, 0]);

        let fdes = parse_eh_frame(&data, 0x1000, 8, false);

        assert_eq!(fdes, vec![Fde { pc_begin: 0x2000, pc_range: 0x40 }]);
    }
}
