use std::{
    collections::VecDeque,
    fmt::Write as _,
    sync::{Arc, Mutex},
};

use tracing::{
    Event, Level, Subscriber,
    field::{Field, Visit},
};
use tracing_subscriber::{EnvFilter, Layer, layer::Context, prelude::*, registry::LookupSpan};

const CAPACITY: usize = 500;
const DEFAULT_FILTER: &str = "warn,idevice_pair=debug,idevice=info";

pub struct Line {
    pub level: Level,
    pub target: String,
    pub message: String,
}

#[derive(Clone, Default)]
pub struct Logs(Arc<Mutex<VecDeque<Line>>>);

impl Logs {
    pub fn read<R>(&self, f: impl FnOnce(&VecDeque<Line>) -> R) -> R {
        f(&self.0.lock().expect("log buffer poisoned"))
    }

    fn push(&self, line: Line) {
        let mut lines = self.0.lock().expect("log buffer poisoned");
        if lines.len() == CAPACITY {
            lines.pop_front();
        }
        lines.push_back(line);
    }
}

pub fn init() -> Logs {
    let logs = Logs::default();
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(DEFAULT_FILTER));

    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer())
        .with(Collector(logs.clone()))
        .init();

    logs
}

struct Collector(Logs);

impl<S: Subscriber + for<'a> LookupSpan<'a>> Layer<S> for Collector {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let mut message = String::new();
        event.record(&mut Fields(&mut message));

        self.0.push(Line {
            level: *event.metadata().level(),
            target: event.metadata().target().to_string(),
            message,
        });
    }
}

struct Fields<'a>(&'a mut String);

impl Visit for Fields<'_> {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if !self.0.is_empty() {
            self.0.push(' ');
        }
        if field.name() == "message" {
            let _ = write!(self.0, "{value:?}");
        } else {
            let _ = write!(self.0, "{}={value:?}", field.name());
        }
    }
}
