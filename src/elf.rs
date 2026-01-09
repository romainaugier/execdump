use std::path::PathBuf;

pub const ELF_MAGIC: u32 = 0x7f454c46;
pub const ELF_MAGIC_ARRAY: [u8; 4] = [0x7F, b'E', b'L', b'F'];

#[derive(Clone, Debug, Default)]
pub struct ELF {

}

pub fn parse_elf(path: &PathBuf) -> Result<ELF, Box<dyn std::error::Error>> {
    let mut elf = ELF::default();

    return Ok(elf);
}
