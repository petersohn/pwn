use clap::{Parser, Subcommand};
use keepass::db::{Group, Node};
use keepass::{Database, DatabaseKey};
use rpassword::prompt_password;
use sha1::{Digest, Sha1};
use std::cell::RefCell;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

use pwn_db::PwnDb;

mod pwn_db;

#[derive(Parser)]
struct ArgParser {
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Subcommand)]
enum Command {
    Convert {
        #[arg(short, long)]
        input: String,
        #[arg(short, long)]
        output: String,
    },

    Keepass {
        #[arg(short, long)]
        db: String,
        #[arg(short, long)]
        pwndb: String,
        #[arg(short, long, default_value = None)]
        keyfile: Option<String>,
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

    let mut hash: [u8; 20] = [0; 20];
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

fn keepass(
    db_path_str: String,
    pwndb_path: String,
    keyfile_path: Option<String>,
) {
    let db_path = Path::new(&db_path_str);
    let mut dbfile = OpenOptions::new().read(true).open(&db_path).unwrap();
    let filename = db_path.file_name().unwrap().to_str().unwrap();
    let password =
        prompt_password(&format!("Password for {filename}: ")).unwrap();
    let key0 = DatabaseKey::new().with_password(&password);
    let key = match keyfile_path {
        None => key0,
        Some(path) => {
            let mut keyfile =
                OpenOptions::new().read(true).open(&path).unwrap();
            key0.with_keyfile(&mut keyfile).unwrap()
        }
    };

    let db = Database::open(&mut dbfile, key).unwrap();
    let pwndbfile = OpenOptions::new().read(true).open(&pwndb_path).unwrap();
    let mut pwndb = PwnDb::new(pwndbfile).unwrap();

    struct StackItem<'a> {
        name: &'a str,
        iter: std::slice::Iter<'a, Node>,
    }

    impl<'a> StackItem<'a> {
        fn new(group: &'a Group) -> StackItem<'a> {
            StackItem {
                name: &group.name,
                iter: group.children.iter(),
            }
        }
    }

    let mut stack: Vec<RefCell<StackItem>> =
        vec![RefCell::new(StackItem::new(&db.root))];
    while let Some(item) = stack.last() {
        let child = item.try_borrow_mut().unwrap().iter.next();
        match child {
            None => {
                stack.pop();
            }
            Some(Node::Group(g)) => {
                stack.push(RefCell::new(StackItem::new(g)));
            }
            Some(Node::Entry(e)) => {
                let mut name = String::new();
                for item in &stack {
                    name += item.try_borrow().unwrap().name;
                    name += " -> ";
                }
                name += e.get_title().unwrap_or("<unnamed>");

                let hash = Sha1::digest(password.as_bytes());
                let pwn_count =
                    pwndb.search(hash.as_slice().try_into().unwrap()).unwrap();
                if pwn_count != 0 {
                    println!("{name}: pwned {pwn_count} times");
                }
            }
        }
    }
}

fn main() {
    let args = ArgParser::parse();
    match args.command {
        Command::Convert { input, output } => convert(input, output),
        Command::Keepass { db, pwndb, keyfile } => keepass(db, pwndb, keyfile),
    }
}
