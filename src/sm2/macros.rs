#![allow(unused_macros)]


#[macro_export]
macro_rules! format_hex {
    ($a: expr) => {
        format!("{:0width$x}", $a, width = 64)
    };

    ($a: expr, $b: expr) => {
        format!("{:0width$x}{:0width$x}", $a, $b, width = 64)
    };

    ($a: expr, $($b: tt)*) => {
        format!("{:0width$x}{}", $a, format_hex!($($b)*), width = 64)
    }
}

#[macro_export]
macro_rules! forward_val_val_binop {
    (impl $imp:ident for $res:ty, $method:ident) => {
        impl $imp<$res> for $res {
            type Output = $res;

            #[inline]
            fn $method(self, other: $res) -> $res {
                $imp::$method(self, &other)
            }
        }
    };
}


#[macro_export]
macro_rules! forward_ref_val_binop {
    (impl $imp:ident for $res:ty, $method:ident) => {
        impl<'a> $imp<$res> for &'a $res {
            type Output = $res;

            #[inline]
            fn $method(self, other: $res) -> $res {
                $imp::$method(self, &other)
            }
        }
    };
}

#[macro_export]
macro_rules! forward_val_ref_binop {
    (impl $imp:ident for $res:ty, $method:ident) => {
        impl<'a> $imp<&'a $res> for $res {
            type Output = $res;

            #[inline]
            fn $method(self, other: &$res) -> $res {
                $imp::$method(&self, other)
            }
        }
    };
}

#[macro_export]
macro_rules! forward_ref_ref_binop {
    (impl $imp:ident for $res:ty, $method:ident) => {
        impl<'a, 'b> $imp<&'b $res> for &'a $res {
            type Output = $res;

            #[inline]
            fn $method(self, other: &$res) -> $res {
                $imp::$method(self.clone(), other)
            }
        }
    };
}


