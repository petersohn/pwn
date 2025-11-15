use std::{
    cmp::Ordering,
    fs::File,
    io::{BufRead, BufReader, Read, Seek, SeekFrom, Write},
};

use sha1::{Digest, Sha1};

const RECORD_LENGTH: u64 = 24;

pub struct PwnDb {
    file: File,
    num_records: u64,
}

fn to_io_error<E>(e: E) -> std::io::Error
where
    E: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    std::io::Error::new(std::io::ErrorKind::Other, e)
}

impl PwnDb {
    pub fn new(file: File) -> std::io::Result<Self> {
        let size = file.metadata()?.len();
        Ok(Self {
            file: file,
            num_records: size / RECORD_LENGTH,
        })
    }

    pub fn search(&mut self, password: &str) -> std::io::Result<u32> {
        let digest = Sha1::digest(password.as_bytes());
        let hash: &[u8; 20] =
            digest.as_slice().try_into().map_err(to_io_error)?;
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

pub fn convert_pwndb(input: &File, output: &mut File) -> std::io::Result<()> {
    let len = input.metadata()?.len() as f64;
    let mut hash: [u8; 20] = [0; 20];
    let mut amount: f64 = 0.0;
    let mut percentage: u8 = 0;
    for line in BufReader::new(input).lines() {
        let l = line?;
        hex::decode_to_slice(&l[0..40], &mut hash).map_err(to_io_error)?;
        let count = l[41..].parse::<u32>().map_err(to_io_error)?;
        output.write(&hash)?;
        output.write(&count.to_be_bytes())?;
        amount += l.len() as f64;
        let new_percentage = ((amount / len) * 100.0) as u8;
        if new_percentage != percentage {
            percentage = new_percentage;
            eprintln!("{percentage}%");
        }
    }

    Ok(())
}

#[cfg(test)]
mod pwndb_test {
    use std::{fs::OpenOptions, path::Path};

    #[test]
    fn convert_and_test() {
        let dir = Path::new("testdata");
        let input_path = dir.join("hashes.txt");
        let output_path = dir.join("hashes.bin");

        {
            let infile =
                OpenOptions::new().read(true).open(&input_path).unwrap();
            let mut outfile = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&output_path)
                .unwrap();
            super::convert_pwndb(&infile, &mut outfile).unwrap();
        }

        let file = OpenOptions::new().read(true).open(&output_path).unwrap();
        let mut pwndb = super::PwnDb::new(file).unwrap();

        let data: Vec<(&'static str, u32)> = vec![
            ("foobar", 0),
            ("one", 1),
            ("two", 2),
            ("three", 3),
            ("four", 4),
            ("five", 5),
            ("six", 6),
            ("seven", 7),
            ("eight", 8),
            ("nine", 9),
            ("ten", 10),
        ];

        for (password, count) in &data {
            eprintln!("{password}");
            assert_eq!(pwndb.search(password).unwrap(), *count);
        }
    }
}
