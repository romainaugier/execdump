use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReaderError {
    UnexpectedEof,
    InvalidPosition,
}

impl fmt::Display for ReaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReaderError::UnexpectedEof => write!(f, "Unexpected end of file"),
            ReaderError::InvalidPosition => write!(f, "Invalid position"),
        }
    }
}

impl std::error::Error for ReaderError {}

pub type ReaderResult<T> = Result<T, ReaderError>;

/// Little Endian Reader
#[derive(Debug)]
pub struct LEReader<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> LEReader<'a> {
    pub fn new(data: &'a [u8]) -> LEReader<'_> {
        return LEReader {
            data,
            position: 0,
        };
    }

    #[inline]
    fn read_bytes(&mut self, n: usize) -> ReaderResult<&[u8]> {
        if self.position + n > self.data.len() {
            return Err(ReaderError::UnexpectedEof);
        }

        let bytes = &self.data[self.position..self.position + n];
        self.position += n;

        return Ok(bytes);
    }

    #[inline]
    fn peek_bytes(&self, n: usize) -> ReaderResult<&[u8]> {
        if self.position + n > self.data.len() {
            return Err(ReaderError::UnexpectedEof);
        }

        return Ok(&self.data[self.position..self.position + n]);
    }

    #[inline]
    pub fn read_u8(&mut self) -> ReaderResult<u8> {
        let bytes = self.read_bytes(1)?;
        return Ok(bytes[0]);
    }

    #[inline]
    pub fn read_i8(&mut self) -> ReaderResult<i8> {
        return Ok(self.read_u8()? as i8);
    }

    #[inline]
    pub fn read_u16(&mut self) -> ReaderResult<u16> {
        let bytes = self.read_bytes(2)?;
        return Ok(u16::from_le_bytes([bytes[0], bytes[1]]));
    }

    #[inline]
    pub fn read_i16(&mut self) -> ReaderResult<i16> {
        let bytes = self.read_bytes(2)?;
        return Ok(i16::from_le_bytes([bytes[0], bytes[1]]));
    }

    #[inline]
    pub fn read_u32(&mut self) -> ReaderResult<u32> {
        let bytes = self.read_bytes(4)?;
        return Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]));
    }

    #[inline]
    pub fn read_i32(&mut self) -> ReaderResult<i32> {
        let bytes = self.read_bytes(4)?;
        return Ok(i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]));
    }

    #[inline]
    pub fn read_u64(&mut self) -> ReaderResult<u64> {
        let bytes = self.read_bytes(8)?;
        return Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5], bytes[6], bytes[7],
        ]));
    }

    #[inline]
    pub fn read_i64(&mut self) -> ReaderResult<i64> {
        let bytes = self.read_bytes(8)?;
        return Ok(i64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5], bytes[6], bytes[7],
        ]));
    }

    #[inline]
    pub fn read_n<const N: usize>(&mut self) -> ReaderResult<[u8; N]> {
        let bytes = self.read_bytes(N)?;
        let mut arr = [0u8; N];
        arr.copy_from_slice(bytes);
        return Ok(arr);
    }

    #[inline]
    pub fn peek(&self) -> ReaderResult<u8> {
        if self.position >= self.data.len() {
            return Err(ReaderError::UnexpectedEof);
        }

        return Ok(self.data[self.position]);
    }

    #[inline]
    pub fn peek_n<const N: usize>(&self) -> ReaderResult<[u8; N]> {
        let bytes = self.peek_bytes(N)?;
        let mut arr = [0u8; N];
        arr.copy_from_slice(bytes);
        return Ok(arr);
    }

    #[inline]
    pub fn position(&self) -> usize {
        return self.position;
    }

    #[inline]
    pub fn set_position(&mut self, pos: usize) -> ReaderResult<()> {
        if pos > self.data.len() {
            return Err(ReaderError::InvalidPosition);
        }

        self.position = pos;

        return Ok(());
    }

    #[inline]
    pub fn remaining(&self) -> usize {
        return self.data.len() - self.position;
    }
}

/// Big Endian Reader
#[derive(Debug)]
pub struct BEReader<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> BEReader<'a> {
    pub fn new(data: &'a [u8]) -> BEReader<'a> {
        return BEReader {
            data,
            position: 0,
        };
    }

    #[inline]
    fn read_bytes(&mut self, n: usize) -> ReaderResult<&[u8]> {
        if self.position + n > self.data.len() {
            return Err(ReaderError::UnexpectedEof);
        }

        let bytes = &self.data[self.position..self.position + n];
        self.position += n;

        return Ok(bytes);
    }

    #[inline]
    fn peek_bytes(&self, n: usize) -> ReaderResult<&[u8]> {
        if self.position + n > self.data.len() {
            return Err(ReaderError::UnexpectedEof);
        }

        return Ok(&self.data[self.position..self.position + n]);
    }

    #[inline]
    pub fn read_u8(&mut self) -> ReaderResult<u8> {
        let bytes = self.read_bytes(1)?;
        return Ok(bytes[0]);
    }

    #[inline]
    pub fn read_i8(&mut self) -> ReaderResult<i8> {
        return Ok(self.read_u8()? as i8);
    }

    #[inline]
    pub fn read_u16(&mut self) -> ReaderResult<u16> {
        let bytes = self.read_bytes(2)?;
        return Ok(u16::from_be_bytes([bytes[0], bytes[1]]));
    }

    #[inline]
    pub fn read_i16(&mut self) -> ReaderResult<i16> {
        let bytes = self.read_bytes(2)?;
        return Ok(i16::from_be_bytes([bytes[0], bytes[1]]));
    }

    #[inline]
    pub fn read_u32(&mut self) -> ReaderResult<u32> {
        let bytes = self.read_bytes(4)?;
        return Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]));
    }

    #[inline]
    pub fn read_i32(&mut self) -> ReaderResult<i32> {
        let bytes = self.read_bytes(4)?;
        return Ok(i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]));
    }

    #[inline]
    pub fn read_u64(&mut self) -> ReaderResult<u64> {
        let bytes = self.read_bytes(8)?;
        return Ok(u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5], bytes[6], bytes[7],
        ]));
    }

    #[inline]
    pub fn read_i64(&mut self) -> ReaderResult<i64> {
        let bytes = self.read_bytes(8)?;
        return Ok(i64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5], bytes[6], bytes[7],
        ]));
    }

    #[inline]
    pub fn read_n<const N: usize>(&mut self) -> ReaderResult<[u8; N]> {
        let bytes = self.read_bytes(N)?;
        let mut arr = [0u8; N];
        arr.copy_from_slice(bytes);
        return Ok(arr);
    }

    #[inline]
    pub fn peek(&self) -> ReaderResult<u8> {
        if self.position >= self.data.len() {
            return Err(ReaderError::UnexpectedEof);
        }
        return Ok(self.data[self.position]);
    }

    #[inline]
    pub fn peek_n<const N: usize>(&self) -> ReaderResult<[u8; N]> {
        let bytes = self.peek_bytes(N)?;
        let mut arr = [0u8; N];
        arr.copy_from_slice(bytes);
        return Ok(arr);
    }

    #[inline]
    pub fn position(&self) -> usize {
        return self.position;
    }

    #[inline]
    pub fn set_position(&mut self, pos: usize) -> ReaderResult<()> {
        if pos > self.data.len() {
            return Err(ReaderError::InvalidPosition);
        }

        self.position = pos;

        return Ok(());
    }

    #[inline]
    pub fn remaining(&self) -> usize {
        return self.data.len() - self.position;
    }
}

/// Reader enum that supports both endianness
#[derive(Debug)]
pub enum Reader<'a> {
    LittleEndian(LEReader<'a>),
    BigEndian(BEReader<'a>),
}

impl<'a> Reader<'a> {
    pub fn new_le(data: &'a [u8]) -> Reader<'a> {
        return Reader::LittleEndian(LEReader::new(data));
    }

    pub fn new_be(data: &'a [u8]) -> Reader<'a> {
        return Reader::BigEndian(BEReader::new(data));
    }

    #[inline]
    pub fn read_u8(&mut self) -> ReaderResult<u8> {
        match self {
            Reader::LittleEndian(r) => r.read_u8(),
            Reader::BigEndian(r) => r.read_u8(),
        }
    }

    #[inline]
    pub fn read_i8(&mut self) -> ReaderResult<i8> {
        match self {
            Reader::LittleEndian(r) => r.read_i8(),
            Reader::BigEndian(r) => r.read_i8(),
        }
    }

    #[inline]
    pub fn read_u16(&mut self) -> ReaderResult<u16> {
        match self {
            Reader::LittleEndian(r) => r.read_u16(),
            Reader::BigEndian(r) => r.read_u16(),
        }
    }

    #[inline]
    pub fn read_i16(&mut self) -> ReaderResult<i16> {
        match self {
            Reader::LittleEndian(r) => r.read_i16(),
            Reader::BigEndian(r) => r.read_i16(),
        }
    }

    #[inline]
    pub fn read_u32(&mut self) -> ReaderResult<u32> {
        match self {
            Reader::LittleEndian(r) => r.read_u32(),
            Reader::BigEndian(r) => r.read_u32(),
        }
    }

    #[inline]
    pub fn read_i32(&mut self) -> ReaderResult<i32> {
        match self {
            Reader::LittleEndian(r) => r.read_i32(),
            Reader::BigEndian(r) => r.read_i32(),
        }
    }

    #[inline]
    pub fn read_u64(&mut self) -> ReaderResult<u64> {
        match self {
            Reader::LittleEndian(r) => r.read_u64(),
            Reader::BigEndian(r) => r.read_u64(),
        }
    }

    #[inline]
    pub fn read_i64(&mut self) -> ReaderResult<i64> {
        match self {
            Reader::LittleEndian(r) => r.read_i64(),
            Reader::BigEndian(r) => r.read_i64(),
        }
    }

    #[inline]
    pub fn read_n<const N: usize>(&mut self) -> ReaderResult<[u8; N]> {
        match self {
            Reader::LittleEndian(r) => r.read_n(),
            Reader::BigEndian(r) => r.read_n(),
        }
    }

    #[inline]
    pub fn peek(&self) -> ReaderResult<u8> {
        match self {
            Reader::LittleEndian(r) => r.peek(),
            Reader::BigEndian(r) => r.peek(),
        }
    }

    #[inline]
    pub fn peek_n<const N: usize>(&self) -> ReaderResult<[u8; N]> {
        match self {
            Reader::LittleEndian(r) => r.peek_n(),
            Reader::BigEndian(r) => r.peek_n(),
        }
    }

    #[inline]
    pub fn position(&self) -> usize {
        match self {
            Reader::LittleEndian(r) => r.position(),
            Reader::BigEndian(r) => r.position(),
        }
    }

    #[inline]
    pub fn set_position(&mut self, pos: usize) -> ReaderResult<()> {
        match self {
            Reader::LittleEndian(r) => r.set_position(pos),
            Reader::BigEndian(r) => r.set_position(pos),
        }
    }

    #[inline]
    pub fn remaining(&self) -> usize {
        match self {
            Reader::LittleEndian(r) => r.remaining(),
            Reader::BigEndian(r) => r.remaining(),
        }
    }
}
