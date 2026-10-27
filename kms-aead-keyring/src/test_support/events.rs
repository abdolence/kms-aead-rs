//! A capture of the events a test's thread logs at `WARN` or above.

use std::collections::BTreeMap;
use std::sync::{Arc, LazyLock, Mutex, PoisonError};

use tracing::field::{Field, Visit};
use tracing::subscriber::{DefaultGuard, NoSubscriber};
use tracing::{Dispatch, Event, Level, Subscriber};
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::Layer;

/// One captured event: its level and its fields by name, strings as they are and other values
/// as `Debug` writes them.
#[derive(Debug, Clone)]
pub(crate) struct CapturedEvent {
    pub(crate) level: Level,
    pub(crate) fields: BTreeMap<&'static str, String>,
}

/// Captures the `WARN` and higher events of the current thread until it is dropped, so a test
/// sees what an operator's alert would.
///
/// Scoped to the thread that installed it: use it in a test on the current-thread runtime
/// `#[tokio::test]` starts, where every task runs on that thread.
///
/// `tracing` caches whether an event site is enabled the first time any thread reaches it. While
/// only one dispatcher is registered it computes that from the reaching thread's own dispatcher
/// alone, so a thread without a capture, running another test, can cache "disabled" for a site
/// this capture's thread reaches later. `ANCHOR` keeps a second dispatcher registered for the
/// life of the process, which makes `tracing` weigh every registered dispatcher instead.
pub(crate) struct EventCapture {
    events: Arc<Mutex<Vec<CapturedEvent>>>,
    _guard: DefaultGuard,
}

static ANCHOR: LazyLock<Dispatch> = LazyLock::new(|| Dispatch::new(NoSubscriber::default()));

impl EventCapture {
    pub(crate) fn install() -> Self {
        LazyLock::force(&ANCHOR);
        let events = Arc::new(Mutex::new(Vec::new()));
        let collector = Collector(Arc::clone(&events)).with_filter(LevelFilter::WARN);
        let guard =
            tracing::subscriber::set_default(tracing_subscriber::registry().with(collector));
        Self {
            events,
            _guard: guard,
        }
    }

    /// The events captured so far.
    pub(crate) fn events(&self) -> Vec<CapturedEvent> {
        self.events
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

struct Collector(Arc<Mutex<Vec<CapturedEvent>>>);

impl<S: Subscriber> Layer<S> for Collector {
    fn on_event(&self, event: &Event<'_>, _: Context<'_, S>) {
        let mut fields = Fields(BTreeMap::new());
        event.record(&mut fields);
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(CapturedEvent {
                level: *event.metadata().level(),
                fields: fields.0,
            });
    }
}

struct Fields(BTreeMap<&'static str, String>);

impl Visit for Fields {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.insert(field.name(), value.to_string());
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.0.insert(field.name(), format!("{value:?}"));
    }
}

mod tests {
    use super::*;

    fn warn() {
        tracing::warn!("emitted");
    }

    #[test]
    fn an_event_site_first_reached_by_another_thread_is_still_captured() {
        let capture = EventCapture::install();

        std::thread::spawn(warn).join().expect("the thread ran");
        warn();

        assert_eq!(capture.events().len(), 1);
    }
}
