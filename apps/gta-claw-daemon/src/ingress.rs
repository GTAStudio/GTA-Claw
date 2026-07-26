//! The HTTP ingress subsystem: a real TCP listener serving the bounded
//! `claw-http-api` router.
//!
//! This is the only subsystem in the process that owns a socket, so it is the
//! only one whose [`ServiceHandle`] reports genuinely bound addresses. The
//! address is always read back from the listener rather than from the
//! configured value, so a reported address is one something is accepting on
//! even when the requested port was `0`.
//!
//! # Why the phases are split the way they are
//!
//! [`SubsystemKind::Ingress`] exists so that every ingress stops accepting
//! before any subsystem drains. If this subsystem kept accepting until
//! `shutdown`, the in-flight set would grow while it was being drained and the
//! resulting [`DrainReport`] would be counting a moving target. So:
//!
//! * `initialize` binds the listener. A port conflict aborts startup before
//!   the process announces readiness.
//! * `start` begins serving.
//! * `quiesce` asks the server to stop accepting and waits until it has
//!   observed the request.
//! * `drain` waits for in-flight requests to finish and reports how many
//!   completed.
//!
//! `quiesce` returns once the serving task has observed the shutdown request
//! and is breaking its accept loop. The residual window is a single task poll,
//! not the length of the drain, which is the property the phase split needs.

use std::io::{self, Write as _};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::Router;
use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;
use claw_application::composition::{
    BoxFuture, DrainReport, ServiceHandle, StartContext, Subsystem, SubsystemDescriptor,
    SubsystemError, SubsystemId, SubsystemKind,
};
use claw_http_api::HttpApi;
use tokio::net::TcpListener;
use tokio::sync::{Mutex, oneshot};
use tokio_util::sync::CancellationToken;

/// Identity of the HTTP ingress subsystem.
///
/// # Panics
///
/// Never. The literal satisfies the identifier grammar.
#[must_use]
pub fn http_ingress_id() -> SubsystemId {
    SubsystemId::new("http-ingress").expect("the literal satisfies the grammar")
}

/// Counts requests whose response has been produced.
#[derive(Debug, Default)]
struct Completed(AtomicU64);

impl Completed {
    fn record(&self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }

    fn count(&self) -> u32 {
        u32::try_from(self.0.load(Ordering::SeqCst)).unwrap_or(u32::MAX)
    }
}

/// State that only exists between `start` and `drain`.
#[derive(Debug)]
struct Serving {
    /// Cancelled to ask the server to stop accepting.
    stop: CancellationToken,
    /// Resolves once the server has observed the stop request.
    accepting_stopped: oneshot::Receiver<()>,
    /// Resolves once every in-flight request has completed.
    finished: oneshot::Receiver<()>,
}

/// A real HTTP listener serving the frozen route inventory.
pub struct HttpIngress {
    id: SubsystemId,
    requested: SocketAddr,
    api: HttpApi,
    completed: Arc<Completed>,
    listener: Mutex<Option<TcpListener>>,
    serving: Mutex<Option<Serving>>,
}

impl std::fmt::Debug for HttpIngress {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HttpIngress")
            .field("id", &self.id)
            .field("requested", &self.requested)
            .field("completed", &self.completed.count())
            .finish_non_exhaustive()
    }
}

impl HttpIngress {
    /// Creates an ingress that will bind `requested` during `initialize`.
    #[must_use]
    pub fn new(requested: SocketAddr, api: HttpApi) -> Self {
        Self {
            id: http_ingress_id(),
            requested,
            api,
            completed: Arc::new(Completed::default()),
            listener: Mutex::new(None),
            serving: Mutex::new(None),
        }
    }

    /// Returns how many requests have produced a response.
    #[must_use]
    pub fn completed(&self) -> u32 {
        self.completed.count()
    }

    fn router(&self) -> Router {
        let completed = Arc::clone(&self.completed);

        self.api.router().layer(axum::middleware::from_fn(
            move |request: Request, next: Next| {
                let completed = Arc::clone(&completed);
                async move {
                    let response: Response = next.run(request).await;
                    completed.record();
                    response
                }
            },
        ))
    }

    fn unavailable(&self, detail: impl Into<String>) -> SubsystemError {
        SubsystemError::unavailable(self.id.clone(), detail)
    }
}

impl Subsystem for HttpIngress {
    fn descriptor(&self) -> SubsystemDescriptor {
        SubsystemDescriptor::new(self.id.clone(), SubsystemKind::Ingress)
    }

    fn initialize<'a>(
        &'a self,
        _context: &'a StartContext,
    ) -> BoxFuture<'a, Result<(), SubsystemError>> {
        Box::pin(async move {
            let listener = TcpListener::bind(self.requested).await.map_err(|error| {
                self.unavailable(format!("cannot bind {}: {error}", self.requested))
            })?;

            *self.listener.lock().await = Some(listener);
            Ok(())
        })
    }

    fn start<'a>(
        &'a self,
        context: &'a StartContext,
    ) -> BoxFuture<'a, Result<ServiceHandle, SubsystemError>> {
        Box::pin(async move {
            let listener = self
                .listener
                .lock()
                .await
                .take()
                .ok_or_else(|| self.unavailable("the listener was not initialized"))?;
            let bound = listener.local_addr().map_err(|error| {
                self.unavailable(format!("cannot read the bound address: {error}"))
            })?;

            let stop = CancellationToken::new();
            let (accepting_stopped, accepting_stopped_rx) = oneshot::channel();
            let (finished, finished_rx) = oneshot::channel();
            let router = self.router();
            let waiting = stop.clone();

            context.spawner().spawn(
                "http-ingress",
                Box::pin(async move {
                    let graceful = async move {
                        waiting.cancelled().await;
                        // Sent from inside the future axum is polling, so a
                        // receipt means the accept loop is being broken rather
                        // than that a request was merely posted.
                        let _ = accepting_stopped.send(());
                    };
                    let served = axum::serve(
                        listener,
                        router.into_make_service_with_connect_info::<SocketAddr>(),
                    )
                    .with_graceful_shutdown(graceful)
                    .await;
                    if let Err(error) = served {
                        let _ = writeln!(
                            io::stderr().lock(),
                            "gta-claw-daemon: http ingress: {error}"
                        );
                    }
                    let _ = finished.send(());
                }),
            )?;

            *self.serving.lock().await = Some(Serving {
                stop,
                accepting_stopped: accepting_stopped_rx,
                finished: finished_rx,
            });

            Ok(ServiceHandle::listening(self.id.clone(), vec![bound]))
        })
    }

    fn quiesce<'a>(&'a self) -> BoxFuture<'a, Result<(), SubsystemError>> {
        Box::pin(async move {
            let Some(serving) = self.serving.lock().await.as_mut().map(|serving| {
                serving.stop.cancel();
                std::mem::replace(&mut serving.accepting_stopped, oneshot::channel().1)
            }) else {
                return Ok(());
            };

            // A closed channel means the serving task ended before it could
            // acknowledge, which also means it is not accepting.
            let _ = serving.await;
            Ok(())
        })
    }

    fn drain<'a>(&'a self) -> BoxFuture<'a, Result<DrainReport, SubsystemError>> {
        Box::pin(async move {
            let Some(finished) = self
                .serving
                .lock()
                .await
                .as_mut()
                .map(|serving| std::mem::replace(&mut serving.finished, oneshot::channel().1))
            else {
                return Ok(DrainReport::clean(self.id.clone(), self.completed.count()));
            };

            let _ = finished.await;
            Ok(DrainReport::clean(self.id.clone(), self.completed.count()))
        })
    }

    fn shutdown<'a>(&'a self) -> BoxFuture<'a, Result<(), SubsystemError>> {
        Box::pin(async move {
            // Tolerates running after a failed initialize: both are already None.
            self.serving.lock().await.take();
            self.listener.lock().await.take();
            Ok(())
        })
    }
}
