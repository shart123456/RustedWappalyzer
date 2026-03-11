use crate::types::Signal;

/// Compute the combined confidence score from a set of detection signals using the Noisy-OR model.
///
/// Noisy-OR treats each signal as an independent noisy sensor: the probability that *none*
/// of the signals fire is the product of their individual "miss" probabilities
/// (`1 - weight/100`). The final score is `1 - P(none fire)`, scaled to [0, 100].
///
/// # Example
/// Two signals with weights 70 and 60 → P(none) = 0.30 × 0.40 = 0.12 → score = 88%
pub(crate) fn compute_noisy_or(signals: &[Signal]) -> u8 {
    if signals.is_empty() { return 0; }
    let p_none: f64 = signals.iter()
        .fold(1.0, |acc, s| acc * (1.0 - s.weight as f64 / 100.0));
    (((1.0 - p_none) * 100.0).round() as u8).min(100)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Signal;

    fn sig(weight: u8) -> Signal {
        Signal { signal_type: "test".into(), value: "v".into(), weight }
    }

    #[test]
    fn empty_signals_zero() {
        assert_eq!(compute_noisy_or(&[]), 0);
    }

    #[test]
    fn single_signal_equals_weight() {
        assert_eq!(compute_noisy_or(&[sig(80)]), 80);
    }

    #[test]
    fn two_signals_noisy_or() {
        // P(none) = 0.30 * 0.40 = 0.12 → score = 88
        assert_eq!(compute_noisy_or(&[sig(70), sig(60)]), 88);
    }

    #[test]
    fn hundred_weight_caps_at_100() {
        assert_eq!(compute_noisy_or(&[sig(100)]), 100);
    }
}
