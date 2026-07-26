//! Total conversions between the ABI types and the Rust-side contract types.
//!
//! Both directions are exhaustive `match`es with no catch-all arm, so adding a
//! variant to either side is a compile error rather than a silent default.

use claw_plugin_api::capability::{EventKind, LogLevel};

use crate::bindings::gta_claw::plugin::host_log::Level as WitLevel;
use crate::bindings::gta_claw::plugin::types::EventKind as WitEventKind;

/// ABI severity to contract severity.
pub(crate) const fn level_from_wit(level: WitLevel) -> LogLevel {
    match level {
        WitLevel::Trace => LogLevel::Trace,
        WitLevel::Debug => LogLevel::Debug,
        WitLevel::Info => LogLevel::Info,
        WitLevel::Warn => LogLevel::Warn,
        WitLevel::Error => LogLevel::Error,
    }
}

/// Contract severity to ABI severity.
///
/// The world only ever carries log levels guest-to-host, so this direction
/// exists to prove the mapping is a bijection.
#[cfg(test)]
pub(crate) const fn level_to_wit(level: LogLevel) -> WitLevel {
    match level {
        LogLevel::Trace => WitLevel::Trace,
        LogLevel::Debug => WitLevel::Debug,
        LogLevel::Info => WitLevel::Info,
        LogLevel::Warn => WitLevel::Warn,
        LogLevel::Error => WitLevel::Error,
    }
}

/// ABI event kind to contract event kind.
pub(crate) const fn event_kind_from_wit(kind: WitEventKind) -> EventKind {
    match kind {
        WitEventKind::SessionStarted => EventKind::SessionStarted,
        WitEventKind::SessionEnded => EventKind::SessionEnded,
        WitEventKind::Message => EventKind::Message,
        WitEventKind::ToolResult => EventKind::ToolResult,
        WitEventKind::ConfigChanged => EventKind::ConfigChanged,
        WitEventKind::Heartbeat => EventKind::Heartbeat,
        WitEventKind::Shutdown => EventKind::Shutdown,
    }
}

/// Contract event kind to ABI event kind.
pub(crate) const fn event_kind_to_wit(kind: EventKind) -> WitEventKind {
    match kind {
        EventKind::SessionStarted => WitEventKind::SessionStarted,
        EventKind::SessionEnded => WitEventKind::SessionEnded,
        EventKind::Message => WitEventKind::Message,
        EventKind::ToolResult => WitEventKind::ToolResult,
        EventKind::ConfigChanged => WitEventKind::ConfigChanged,
        EventKind::Heartbeat => WitEventKind::Heartbeat,
        EventKind::Shutdown => WitEventKind::Shutdown,
    }
}

#[cfg(test)]
mod tests {
    use claw_plugin_api::capability::{EventKind, LogLevel};

    use super::{event_kind_from_wit, event_kind_to_wit, level_from_wit, level_to_wit};
    use crate::bindings::gta_claw::plugin::host_log::Level as WitLevel;
    use crate::bindings::gta_claw::plugin::types::EventKind as WitEventKind;

    const WIT_LEVELS: [WitLevel; 5] = [
        WitLevel::Trace,
        WitLevel::Debug,
        WitLevel::Info,
        WitLevel::Warn,
        WitLevel::Error,
    ];

    const WIT_EVENT_KINDS: [WitEventKind; 7] = [
        WitEventKind::SessionStarted,
        WitEventKind::SessionEnded,
        WitEventKind::Message,
        WitEventKind::ToolResult,
        WitEventKind::ConfigChanged,
        WitEventKind::Heartbeat,
        WitEventKind::Shutdown,
    ];

    #[test]
    fn every_abi_level_round_trips_through_the_contract_type() {
        for level in WIT_LEVELS {
            assert_eq!(level_to_wit(level_from_wit(level)), level);
        }
        assert_eq!(WIT_LEVELS.len(), 5);
    }

    #[test]
    fn every_contract_level_round_trips_through_the_abi_type() {
        let levels = [
            LogLevel::Trace,
            LogLevel::Debug,
            LogLevel::Info,
            LogLevel::Warn,
            LogLevel::Error,
        ];
        for level in levels {
            assert_eq!(level_from_wit(level_to_wit(level)), level);
        }
    }

    #[test]
    fn the_level_mapping_is_order_preserving() {
        let ordered: Vec<LogLevel> = WIT_LEVELS.into_iter().map(level_from_wit).collect();
        let mut sorted = ordered.clone();
        sorted.sort_unstable();
        assert_eq!(ordered, sorted);
        assert_eq!(ordered.first(), Some(&LogLevel::Trace));
        assert_eq!(ordered.last(), Some(&LogLevel::Error));
    }

    #[test]
    fn every_abi_event_kind_round_trips_through_the_contract_type() {
        for kind in WIT_EVENT_KINDS {
            assert_eq!(event_kind_to_wit(event_kind_from_wit(kind)), kind);
        }
        assert_eq!(WIT_EVENT_KINDS.len(), EventKind::ALL.len());
    }

    #[test]
    fn every_contract_event_kind_round_trips_through_the_abi_type() {
        for kind in EventKind::ALL {
            assert_eq!(event_kind_from_wit(event_kind_to_wit(kind)), kind);
        }
    }

    #[test]
    fn the_event_kind_mapping_is_a_bijection() {
        let mapped: Vec<EventKind> = WIT_EVENT_KINDS
            .into_iter()
            .map(event_kind_from_wit)
            .collect();
        let unique: std::collections::BTreeSet<EventKind> = mapped.iter().copied().collect();
        assert_eq!(unique.len(), WIT_EVENT_KINDS.len());
        assert_eq!(
            unique,
            EventKind::ALL
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>()
        );
    }
}
