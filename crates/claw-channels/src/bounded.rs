use std::collections::VecDeque;
use std::num::NonZeroUsize;

#[derive(Debug)]
pub(crate) struct BoundedQueue<T> {
    capacity: NonZeroUsize,
    values: VecDeque<T>,
}

impl<T> BoundedQueue<T> {
    pub(crate) const fn new(capacity: NonZeroUsize) -> Self {
        Self {
            capacity,
            values: VecDeque::new(),
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.values.len()
    }

    pub(crate) fn remaining_capacity(&self) -> usize {
        self.capacity.get().saturating_sub(self.values.len())
    }

    pub(crate) fn push(&mut self, value: T) -> Result<(), T> {
        if self.values.len() == self.capacity.get() {
            return Err(value);
        }
        self.values.push_back(value);
        Ok(())
    }

    pub(crate) fn pop(&mut self) -> Option<T> {
        self.values.pop_front()
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &T> {
        self.values.iter()
    }

    pub(crate) fn clear(&mut self) {
        self.values.clear();
    }

    pub(crate) fn truncate(&mut self, len: usize) {
        self.values.truncate(len);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_refuses_overflow_without_losing_the_value() {
        let mut queue = BoundedQueue::new(NonZeroUsize::new(1).expect("non-zero"));
        assert_eq!(queue.push("first"), Ok(()));
        assert_eq!(queue.push("second"), Err("second"));
        assert_eq!(queue.len(), 1);
        assert_eq!(queue.pop(), Some("first"));
        assert_eq!(queue.pop(), None);
    }
}
