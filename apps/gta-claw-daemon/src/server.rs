//! Listener lifecycle for the headless daemon.
//!
//! Shutdown handles are registered before the process announces that it is
//! listening, so a signal that arrives immediately after the announcement is
//! observed by this process rather than by the default disposition.

use std::io;
use std::net::SocketAddr;

use axum::Router;
use tokio::net::TcpListener;

pub(crate) use platform::ShutdownSignals;

/// Serves the router until a shutdown signal drains the listener.
///
/// Returns the name of the signal that initiated shutdown once every in-flight
/// request has completed.
pub(crate) async fn serve(
    listener: TcpListener,
    router: Router,
    signals: ShutdownSignals,
) -> io::Result<&'static str> {
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let graceful = async move {
        let reason = signals.recv().await;
        let _ = sender.send(reason);
    };

    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(graceful)
    .await?;

    Ok(receiver.await.unwrap_or("unknown"))
}

#[cfg(unix)]
mod platform {
    use std::io;

    use tokio::signal::unix::{Signal, SignalKind, signal};

    /// Registered POSIX termination signals.
    pub(crate) struct ShutdownSignals {
        terminate: Signal,
        interrupt: Signal,
    }

    impl ShutdownSignals {
        /// Installs handlers for `SIGTERM` and `SIGINT`.
        pub(crate) fn register() -> io::Result<Self> {
            Ok(Self {
                terminate: signal(SignalKind::terminate())?,
                interrupt: signal(SignalKind::interrupt())?,
            })
        }

        /// Resolves with the name of the first signal received.
        pub(crate) async fn recv(mut self) -> &'static str {
            tokio::select! {
                _ = self.terminate.recv() => "SIGTERM",
                _ = self.interrupt.recv() => "SIGINT",
            }
        }
    }
}

#[cfg(windows)]
mod platform {
    use std::io;

    use tokio::signal::windows::{
        CtrlBreak, CtrlC, CtrlClose, CtrlShutdown, ctrl_break, ctrl_c, ctrl_close, ctrl_shutdown,
    };

    /// Registered Windows console control events.
    pub(crate) struct ShutdownSignals {
        interrupt: CtrlC,
        break_event: CtrlBreak,
        close: CtrlClose,
        shutdown: CtrlShutdown,
    }

    impl ShutdownSignals {
        /// Installs handlers for the console control events that end a service.
        pub(crate) fn register() -> io::Result<Self> {
            Ok(Self {
                interrupt: ctrl_c()?,
                break_event: ctrl_break()?,
                close: ctrl_close()?,
                shutdown: ctrl_shutdown()?,
            })
        }

        /// Resolves with the name of the first console control event received.
        pub(crate) async fn recv(mut self) -> &'static str {
            tokio::select! {
                _ = self.interrupt.recv() => "CTRL_C",
                _ = self.break_event.recv() => "CTRL_BREAK",
                _ = self.close.recv() => "CTRL_CLOSE",
                _ = self.shutdown.recv() => "CTRL_SHUTDOWN",
            }
        }
    }
}
