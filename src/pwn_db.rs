use std::{
    cmp::Ordering,
    fs::File,
    io::{Read, Seek, SeekFrom},
};

const RECORD_LENGTH: u64 = 24;

pub struct PwnDb {
    file: File,
    num_records: u64,
}

impl PwnDb {
    pub fn new(file: File) -> std::io::Result<Self> {
        let size = file.metadata()?.len();
        Ok(Self {
            file: file,
            num_records: size / RECORD_LENGTH,
        })
    }

    pub fn search(&mut self, hash: &[u8; 20]) -> std::io::Result<u32> {
        let mut begin: u64 = 0;
        let mut end = self.num_records;
        let mut current_hash: [u8; 20] = [0; 20];
        while begin != end {
            let current = (begin + end) / 2;
            self.file.seek(SeekFrom::Start(current * RECORD_LENGTH))?;
            self.file.read_exact(&mut current_hash)?;
            match hash.cmp(&current_hash) {
                Ordering::Less => end = current,
                Ordering::Greater => begin = current + 1,
                Ordering::Equal => {
                    let mut count: [u8; 4] = [0; 4];
                    self.file.read_exact(&mut count)?;
                    return Ok(u32::from_be_bytes(count));
                }
            }
        }

        Ok(0)
    }
}
