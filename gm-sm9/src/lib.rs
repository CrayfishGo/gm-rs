
#![doc = include_str!("../README.md")]



pub(crate) mod algorithm;
pub mod key;
pub mod fields;
pub mod u256;

pub fn add(left: usize, right: usize) -> usize {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
