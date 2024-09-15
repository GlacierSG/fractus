use std::collections::HashMap;
use colored::*;
use std::borrow::Borrow;
use std::fmt;

pub struct Replacer {
    pub tokens: Vec<String>,
    pub map: HashMap<String, String>,
    pub alphabet: Vec<String>,
}


impl fmt::Display for Replacer {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for c in &self.tokens {
            if let Some(color) = self.map.get(c) {
                write!(f, "{}", color.red())?;
            } else {
                write!(f, "{}", c)?;
            }
        }
        writeln!(f)
    }
}

impl Replacer {
    pub fn new() -> Self {
        Self {
            tokens: vec![],
            map: HashMap::new(),
            alphabet: vec![],
        }
    }
    pub fn tokens(&mut self, v: impl Borrow<str>) {
        let v = v.borrow();

        for c in v.chars() {
            self.tokens.push(c.to_string());
        }
    }
    pub fn replace(&mut self, lhs: impl Borrow<str>, rhs: impl Borrow<str>) {
        let lhs = lhs.borrow();
        let rhs = rhs.borrow();

        self.map.insert(lhs.to_string(), rhs.to_string());
    }
    pub fn alphabet(&mut self, token: impl Borrow<str>) {
        let token = token.borrow();

        for c in token.chars() {
            self.alphabet.push(c.to_string());
        }
    }
    pub fn ceasar(&mut self, key: i32) {
        if self.alphabet.len() == 0 {
            panic!("missing alphabet");
        }
        for i in 0..self.alphabet.len() {
            let l = self.alphabet.len() as i32;
            let a: usize = ((key % l) + l).try_into().unwrap();
            let new_i: usize = (i + a) % self.alphabet.len();
            self.map.insert(self.alphabet[i].clone(), self.alphabet[new_i].clone());
        }
    }
    pub fn result(&self) -> String {
        let mut s = String::new();
        for c in &self.tokens {
            if self.map.contains_key(c) {
                s.push_str(&self.map[c]);
            }
            else {
                s.push_str(c);
            }
        }
        s
    }
    
    pub fn count(&self) -> Vec<(String, usize)> {
        let mut m = HashMap::new();
        for s in &self.tokens {
            *m.entry(s.clone()).or_insert(0) += 1; 
        }
        
        let mut v: Vec<(String, usize)> = m.into_iter().collect();
        v.sort_by(|a, b| b.1.cmp(&a.1));
        v
    }
}
