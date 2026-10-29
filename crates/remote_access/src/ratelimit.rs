//! Small in-memory rate limiting primitives: a sliding-window counter, an
//! escalating lockout, and a byte token bucket for input throttling.
use std::collections::VecDeque;

/// Allows at most `max` events per `window_secs`.
#[derive(Debug, Clone)]
pub struct SlidingWindow {
    max: usize,
    window_secs: i64,
    hits: VecDeque<i64>,
}

impl SlidingWindow {
    pub fn new(max: usize, window_secs: i64) -> Self {
        Self {
            max,
            window_secs,
            hits: VecDeque::new(),
        }
    }

    /// Records an event at `now`. `Err(retry_after_secs)` when over the limit
    /// (the rejected event is not recorded, so spamming does not extend it).
    pub fn check(&mut self, now: i64) -> Result<(), u64> {
        while let Some(&oldest) = self.hits.front() {
            if now - oldest >= self.window_secs {
                self.hits.pop_front();
            } else {
                break;
            }
        }
        if self.hits.len() >= self.max {
            let oldest = self.hits.front().copied().unwrap_or(now);
            let retry = (oldest + self.window_secs - now).max(1);
            return Err(retry as u64);
        }
        self.hits.push_back(now);
        Ok(())
    }
}

/// Failure counter that starts an escalating lockout every `threshold`
/// failures. The default schedule is 30 s, 1 m, 5 m, 30 m (then stays at 30 m).
#[derive(Debug, Clone)]
pub struct Lockout {
    schedule: Vec<u64>,
    threshold: u32,
    failures: u32,
    level: usize,
    locked_until: Option<i64>,
}

impl Lockout {
    pub const DEFAULT_SCHEDULE: [u64; 4] = [30, 60, 300, 1800];

    pub fn new(schedule: Vec<u64>, threshold: u32) -> Self {
        assert!(!schedule.is_empty() && threshold > 0);
        Self {
            schedule,
            threshold,
            failures: 0,
            level: 0,
            locked_until: None,
        }
    }

    /// Seconds remaining if locked at `now`.
    pub fn retry_after(&self, now: i64) -> Option<u64> {
        match self.locked_until {
            Some(until) if until > now => Some((until - now) as u64),
            _ => None,
        }
    }

    pub fn locked_until(&self, now: i64) -> Option<i64> {
        self.retry_after(now)
            .map(|_| self.locked_until.unwrap_or(now))
    }

    /// Records a failure; returns true if this failure started a lockout.
    pub fn record_failure(&mut self, now: i64) -> bool {
        self.failures += 1;
        if self.failures < self.threshold {
            return false;
        }
        self.failures = 0;
        let secs = self.schedule[self.level.min(self.schedule.len() - 1)];
        self.level += 1;
        self.locked_until = Some(now + secs as i64);
        true
    }

    /// Clears all counters (successful pairing or explicit PC-side reset).
    pub fn reset(&mut self) {
        self.failures = 0;
        self.level = 0;
        self.locked_until = None;
    }
}

impl Default for Lockout {
    fn default() -> Self {
        Self::new(Self::DEFAULT_SCHEDULE.to_vec(), 3)
    }
}

/// Byte token bucket (e.g. 1 MiB/s with a 256 KiB burst for phone input).
#[derive(Debug, Clone)]
pub struct TokenBucket {
    rate_per_sec: f64,
    burst: f64,
    available: f64,
    last_ms: Option<u64>,
}

impl TokenBucket {
    pub fn new(rate_per_sec: u64, burst: u64) -> Self {
        Self {
            rate_per_sec: rate_per_sec as f64,
            burst: burst as f64,
            available: burst as f64,
            last_ms: None,
        }
    }

    /// Takes `n` tokens at monotonic time `now_ms`; false if not enough.
    pub fn try_take(&mut self, n: u64, now_ms: u64) -> bool {
        if let Some(last) = self.last_ms {
            let dt = now_ms.saturating_sub(last) as f64 / 1000.0;
            self.available = (self.available + dt * self.rate_per_sec).min(self.burst);
        }
        self.last_ms = Some(now_ms);
        if (n as f64) <= self.available {
            self.available -= n as f64;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_limits_and_recovers() {
        let mut w = SlidingWindow::new(5, 60);
        for i in 0..5 {
            assert!(w.check(100 + i).is_ok());
        }
        let retry = w.check(105).unwrap_err();
        assert_eq!(retry, 55);
        // Rejected events were not recorded.
        assert_eq!(w.check(120).unwrap_err(), 40);
        assert!(w.check(160).is_ok());
    }

    #[test]
    fn lockout_schedule_escalates_and_caps() {
        let mut l = Lockout::default();
        let mut now = 1000;
        let mut got = vec![];
        for _ in 0..6 {
            assert!(!l.record_failure(now));
            assert!(!l.record_failure(now));
            assert!(l.record_failure(now));
            let s = l.retry_after(now).unwrap();
            got.push(s);
            now += s as i64;
            assert!(l.retry_after(now).is_none());
        }
        assert_eq!(got, vec![30, 60, 300, 1800, 1800, 1800]);
    }

    #[test]
    fn lockout_reset() {
        let mut l = Lockout::default();
        for _ in 0..3 {
            l.record_failure(0);
        }
        assert!(l.retry_after(1).is_some());
        l.reset();
        assert!(l.retry_after(1).is_none());
        for _ in 0..3 {
            l.record_failure(0);
        }
        assert_eq!(l.retry_after(0), Some(30));
        assert_eq!(l.locked_until(0), Some(30));
    }

    #[test]
    fn bucket_burst_and_refill() {
        let mut b = TokenBucket::new(1000, 500);
        assert!(b.try_take(500, 0));
        assert!(!b.try_take(1, 0));
        assert!(b.try_take(100, 100)); // refilled 100
        assert!(!b.try_take(1, 100));
        assert!(b.try_take(500, 10_000)); // capped at burst
        assert!(!b.try_take(501, 20_000));
    }
}
