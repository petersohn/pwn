use clap::{Parser, Subcommand};
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};

#[derive(Parser)]
struct ArgParser {
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Subcommand)]
enum Command {
    /// Query ski area from OSM
    Convert {
        /// Name of the ski area (case insensitive, regex)
        #[arg(short, long)]
        input: String,
        #[arg(short, long)]
        output: String,
    },
}

fn convert(input: String, output: String) {
    let infile = OpenOptions::new().read(true).open(&input).unwrap();
    let len = infile.metadata().unwrap().len() as f64;

    let mut outfile = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&output)
        .unwrap();

    let mut hash: Vec<u8> = Vec::new();
    hash.resize(20, 0);
    let mut amount: f64 = 0.0;
    let mut percentage: u8 = 0;
    for line in BufReader::new(infile).lines().map(|l| l.unwrap()) {
        hex::decode_to_slice(&line[0..40], &mut hash).unwrap();
        let count = line[41..].parse::<u32>().unwrap();
        outfile.write(&hash).unwrap();
        outfile.write(&count.to_be_bytes()).unwrap();
        amount += line.len() as f64;
        let new_percentage = ((amount / len) * 100.0) as u8;
        if new_percentage != percentage {
            percentage = new_percentage;
            println!("{percentage}%");
        }
    }
}

fn main() {
    let args = ArgParser::parse();
    match args.command {
        Command::Convert { input, output } => convert(input, output),
    }
}
