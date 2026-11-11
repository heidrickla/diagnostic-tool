//! Saturating sums and products, only for what the program itself holds or spends: sizes of
//! what it keeps in memory, counts of what it found and budget charges. A place or length
//! read from a disk never goes through here; it is combined only with checked arithmetic,
//! so a step that overflows is damage, never a number that later steps bring back.

/// An unsigned count that saturates.
pub(crate) trait Count: Copy {
    fn plus(self, other: Self) -> Self;
    fn times(self, other: Self) -> Self;
    fn minus(self, other: Self) -> Self;
}

macro_rules! count {
    ($($t:ty),*) => {$(
        impl Count for $t {
            fn plus(self, other: Self) -> Self {
                self.saturating_add(other)
            }
            fn times(self, other: Self) -> Self {
                self.saturating_mul(other)
            }
            fn minus(self, other: Self) -> Self {
                self.saturating_sub(other)
            }
        }
    )*};
}

count!(u64, usize);

pub(crate) fn add<T: Count>(a: T, b: T) -> T {
    a.plus(b)
}

pub(crate) fn mul<T: Count>(a: T, b: T) -> T {
    a.times(b)
}

/// What is left of `a` after `b`, none when `b` is more.
pub(crate) fn sub<T: Count>(a: T, b: T) -> T {
    a.minus(b)
}

/// The sum of counts, from `start`.
pub(crate) fn sum<T: Count>(start: T, counts: impl IntoIterator<Item = T>) -> T {
    counts.into_iter().fold(start, add)
}
