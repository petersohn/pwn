use crate::pwn_db::PwnDb;
use keepass::db::{Group, Node};
use std::cell::RefCell;

pub fn analyze_keepass_db(
    root: &keepass::db::Group,
    pwndb: &mut PwnDb,
) -> Vec<(Vec<String>, u32)> {
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
        vec![RefCell::new(StackItem::new(root))];
    let mut result = Vec::new();
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
                if let Some(password) = e.get_password() {
                    let pwn_count = pwndb.search(password).unwrap();
                    if pwn_count != 0 {
                        let mut names: Vec<String> = stack
                            .iter()
                            .map(|i| i.try_borrow().unwrap().name.to_string())
                            .collect();
                        names.push(e.get_title().unwrap_or("").to_string());
                        result.push((names, pwn_count));
                    }
                }
            }
        }
    }

    result
}
