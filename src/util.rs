pub trait ArithExt<T> {
    /** Add operator with standard overflow semantics */
    fn platform_add(self, val: T) -> T;

    /** Subtraction operator with standard overflow semantics */
    fn platform_sub(self, val: T) -> T;
}

impl ArithExt<u32> for u32 {
    fn platform_add(self, val: u32) -> u32 {
        let (res, _) = self.overflowing_add(val);
        res
    }

    fn platform_sub(self, val: u32) -> u32 {
        let (res, _) = self.overflowing_sub(val);
        res
    }
}

/**
 * Taken from https://stackoverflow.com/a/56677696/13300239
 */

pub trait CollectRev: Iterator {
    fn collect_rev<B>(self) -> B
    where
        B: FromIteratorRev<Self::Item>,
        Self: Sized,
    {
        B::from_iter_rev(self)
    }
}

impl<I: Iterator> CollectRev for I {}

pub trait FromIteratorRev<T> {
    fn from_iter_rev(iter: impl IntoIterator<Item = T>) -> Self;
}

impl<T> FromIteratorRev<T> for Vec<T> {
    fn from_iter_rev(iter: impl IntoIterator<Item = T>) -> Self {
        let mut v: Self = iter.into_iter().collect();
        v.reverse();
        v
    }
}
