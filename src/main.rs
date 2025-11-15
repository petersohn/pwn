use clap::{Parser, Subcommand};
use keepass::db::{Group, Node};
use keepass::{Database, DatabaseKey};
use rpassword::prompt_password;
use std::cell::RefCell;
use std::fs::OpenOptions;
use std::path::Path;

use pwn_db::PwnDb;

use crate::pwn_db::convert_pwndb;

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
    let mut outfile = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&output)
        .unwrap();

    convert_pwndb(&infile, &mut outfile).unwrap();
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

                let pwn_count = pwndb.search(&password).unwrap();
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
