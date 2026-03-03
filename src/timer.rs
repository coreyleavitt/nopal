use std::collections::BinaryHeap;
use std::cmp::Reverse;
use std::time::{Duration, Instant};

/// Unique identifier for a scheduled timer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TimerId(pub u64);

/// What the timer is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerKind {
    /// Health probe for interface at the given index.
    Probe(usize),
    /// Probe timeout for interface at the given index.
    ProbeTimeout(usize),
    /// Dampening decay tick for interface at the given index.
    DampenDecay(usize),
    /// IPC client timeout.
    IpcTimeout(usize),
}

#[derive(Debug)]
struct Entry {
    deadline: Instant,
    id: TimerId,
    kind: TimerKind,
}

/// Note: PartialEq/Ord compare only `deadline` because Entry is solely used
/// in a BinaryHeap where ordering is all that matters. Do not use Entry in
/// HashSet/BTreeSet where structural equality is required.
impl PartialEq for Entry {
    fn eq(&self, other: &Self) -> bool {
        self.deadline == other.deadline && self.id == other.id
    }
}

impl Eq for Entry {}

impl PartialOrd for Entry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Entry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Natural ordering by deadline; BinaryHeap<Reverse<Entry>> gives min-heap behavior.
        self.deadline.cmp(&other.deadline)
    }
}

/// Simple timer wheel backed by a min-heap.
///
/// Uses `BinaryHeap<Reverse<Entry>>` for O(log n) insert and O(1) peek.
/// Adequate for the expected number of timers (2-3 per interface, ~10 total).
pub struct TimerWheel {
    heap: BinaryHeap<Reverse<Entry>>,
    next_id: u64,
}

impl TimerWheel {
    pub fn new() -> Self {
        Self {
            heap: BinaryHeap::new(),
            next_id: 0,
        }
    }

    /// Schedule a timer to fire after `delay` from now.
    pub fn schedule(&mut self, delay: Duration, kind: TimerKind) -> TimerId {
        let id = TimerId(self.next_id);
        self.next_id += 1;
        self.heap.push(Reverse(Entry {
            deadline: Instant::now() + delay,
            id,
            kind,
        }));
        id
    }

    /// Schedule a timer to fire at an exact instant.
    #[allow(dead_code)]
    pub fn schedule_at(&mut self, deadline: Instant, kind: TimerKind) -> TimerId {
        let id = TimerId(self.next_id);
        self.next_id += 1;
        self.heap.push(Reverse(Entry {
            deadline,
            id,
            kind,
        }));
        id
    }

    /// Returns the duration until the next timer fires, or `None` if empty.
    pub fn next_deadline(&self) -> Option<Duration> {
        self.heap.peek().map(|Reverse(entry)| {
            let now = Instant::now();
            if entry.deadline <= now {
                Duration::ZERO
            } else {
                entry.deadline - now
            }
        })
    }

    /// Pop all timers whose deadline has passed into the provided buffer.
    /// The buffer is cleared before use to allow reuse across calls.
    pub fn poll_into(&mut self, fired: &mut Vec<(TimerId, TimerKind)>) {
        fired.clear();
        let now = Instant::now();
        while let Some(Reverse(entry)) = self.heap.peek() {
            if entry.deadline <= now {
                let Reverse(entry) = self.heap.pop().unwrap();
                fired.push((entry.id, entry.kind));
            } else {
                break;
            }
        }
    }

    /// Cancel all timers matching a predicate on their kind.
    pub fn cancel_by_kind<F>(&mut self, pred: F)
    where
        F: Fn(&TimerKind) -> bool,
    {
        // Use into_vec() + retain + BinaryHeap::from() to reuse the
        // backing allocation instead of collecting into a new heap.
        let mut vec = std::mem::take(&mut self.heap).into_vec();
        vec.retain(|Reverse(e)| !pred(&e.kind));
        self.heap = BinaryHeap::from(vec);
    }

    /// Returns true if no timers are scheduled.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.heap.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schedule_and_poll() {
        let mut tw = TimerWheel::new();
        tw.schedule(Duration::ZERO, TimerKind::Probe(0));
        tw.schedule(Duration::from_secs(3600), TimerKind::Probe(1));

        let mut fired = Vec::new();
        tw.poll_into(&mut fired);
        assert_eq!(fired.len(), 1);
        assert_eq!(fired[0].1, TimerKind::Probe(0));

        // The distant timer should still be pending
        assert!(!tw.is_empty());
        assert!(tw.next_deadline().unwrap() > Duration::from_secs(3500));
    }

    #[test]
    fn cancel_by_kind() {
        let mut tw = TimerWheel::new();
        tw.schedule(Duration::from_secs(1), TimerKind::Probe(0));
        tw.schedule(Duration::from_secs(1), TimerKind::ProbeTimeout(0));
        tw.schedule(Duration::from_secs(1), TimerKind::Probe(1));

        tw.cancel_by_kind(|k| matches!(k, TimerKind::Probe(0) | TimerKind::ProbeTimeout(0)));
        // Only Probe(1) should remain
        assert_eq!(tw.heap.len(), 1);
    }
}
