use std::io::{Cursor, Read};

/// Little Endian Reader
#[derive(Debug)]
pub struct LEReader<'a> {
    cursor: Cursor<&'a Vec<u8>>,
}

impl LEReader<'_> {
    pub fn new(data: &Vec<u8>) -> LEReader<'_> {
        return LEReader {
            cursor: Cursor::new(data),
        };
    }

    pub fn read_u8(&mut self) -> std::io::Result<u8> {
        let mut bytes = [0; 1];
        self.cursor.read_exact(&mut bytes)?;
        return Ok(u8::from_le_bytes(bytes));
    }

    pub fn read_i8(&mut self) -> std::io::Result<i8> {
        let mut bytes = [0; 1];
        self.cursor.read_exact(&mut bytes)?;
        return Ok(i8::from_le_bytes(bytes));
    }

    pub fn read_u16(&mut self) -> std::io::Result<u16> {
        let mut bytes = [0; 2];
        self.cursor.read_exact(&mut bytes)?;
        return Ok(u16::from_le_bytes(bytes));
    }

    pub fn read_i16(&mut self) -> std::io::Result<i16> {
        let mut bytes = [0; 2];
        self.cursor.read_exact(&mut bytes)?;
        return Ok(i16::from_le_bytes(bytes));
    }

    pub fn read_u32(&mut self) -> std::io::Result<u32> {
        let mut bytes = [0; 4];
        self.cursor.read_exact(&mut bytes)?;
        return Ok(u32::from_le_bytes(bytes));
    }

    pub fn read_i32(&mut self) -> std::io::Result<i32> {
        let mut bytes = [0; 4];
        self.cursor.read_exact(&mut bytes)?;
        return Ok(i32::from_le_bytes(bytes));
    }

    pub fn read_u64(&mut self) -> std::io::Result<u64> {
        let mut bytes = [0; 8];
        self.cursor.read_exact(&mut bytes)?;
        return Ok(u64::from_le_bytes(bytes));
    }

    pub fn read_i64(&mut self) -> std::io::Result<i64> {
        let mut bytes = [0; 8];
        self.cursor.read_exact(&mut bytes)?;
        return Ok(i64::from_le_bytes(bytes));
    }
}

/// Big Endian Reader
#[derive(Debug)]
pub struct BEReader<'a> {
    cursor: Cursor<&'a Vec<u8>>,
}

impl BEReader<'_> {
    pub fn new(data: &Vec<u8>) -> BEReader<'_> {
        return BEReader {
            cursor: Cursor::new(data),
        };
    }

    pub fn read_u8(&mut self) -> std::io::Result<u8> {
        let mut bytes = [0; 1];
        self.cursor.read_exact(&mut bytes)?;
        return Ok(u8::from_be_bytes(bytes));
    }

    pub fn read_i8(&mut self) -> std::io::Result<i8> {
        let mut bytes = [0; 1];
        self.cursor.read_exact(&mut bytes)?;
        return Ok(i8::from_be_bytes(bytes));
    }

    pub fn read_u16(&mut self) -> std::io::Result<u16> {
        let mut bytes = [0; 2];
        self.cursor.read_exact(&mut bytes)?;
        return Ok(u16::from_be_bytes(bytes));
    }

    pub fn read_i16(&mut self) -> std::io::Result<i16> {
        let mut bytes = [0; 2];
        self.cursor.read_exact(&mut bytes)?;
        return Ok(i16::from_be_bytes(bytes));
    }

    pub fn read_u32(&mut self) -> std::io::Result<u32> {
        let mut bytes = [0; 4];
        self.cursor.read_exact(&mut bytes)?;
        return Ok(u32::from_be_bytes(bytes));
    }

    pub fn read_i32(&mut self) -> std::io::Result<i32> {
        let mut bytes = [0; 4];
        self.cursor.read_exact(&mut bytes)?;
        return Ok(i32::from_be_bytes(bytes));
    }

    pub fn read_u64(&mut self) -> std::io::Result<u64> {
        let mut bytes = [0; 8];
        self.cursor.read_exact(&mut bytes)?;
        return Ok(u64::from_be_bytes(bytes));
    }

    pub fn read_i64(&mut self) -> std::io::Result<i64> {
        let mut bytes = [0; 8];
        self.cursor.read_exact(&mut bytes)?;
        return Ok(i64::from_be_bytes(bytes));
    }
}
