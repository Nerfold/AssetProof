use common::types::Delta;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RangePolicy {
    pub max_abs_epoch_delta: i128,
    pub max_abs_single_delta: i128,
}

impl RangePolicy {
    pub fn conservative_demo() -> Self {
        Self {
            max_abs_epoch_delta: 1_i128 << 96,
            max_abs_single_delta: 1_i128 << 80,
        }
    }
}

pub fn check_public_delta_range(deltas: &[Delta], policy: &RangePolicy) -> Result<(), String> {
    let mut total = 0i128;
    for delta in deltas {
        if delta.delta.unsigned_abs() > policy.max_abs_single_delta as u128 {
            return Err("delta exceeds configured integer range".to_string());
        }
        total = total
            .checked_add(delta.delta)
            .ok_or_else(|| "delta sum overflowed i128".to_string())?;
    }
    if total.unsigned_abs() > policy.max_abs_epoch_delta as u128 {
        return Err("epoch delta sum exceeds configured integer range".to_string());
    }
    Ok(())
}
