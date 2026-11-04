//! logind session state and suspend-delay inhibitor ownership.
//!
//! Only the system bus socket is used; environment-provided bus addresses are
//! deliberately ignored. Signals are bound to logind's root-owned unique bus
//! name. Losing that owner, the connection, or a subscription fails closed.

use std::collections::HashMap;
use std::io;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use futures_util::StreamExt;
use tokio::sync::oneshot;
use zbus::{
    Connection, DynamicTuple, MatchRule, Message, MessageStream, OwnedFd, OwnedObjectPath,
    OwnedVariant, Proxy, message::Type, proxy::CacheProperties,
};

use super::portable::{Acknowledgement, EventSink, FailureCallback, event_stream};
use super::{NativeSessionEvent, SessionObserver};

const SERVICE: &str = "org.freedesktop.login1";
const MANAGER_PATH: &str = "/org/freedesktop/login1";
const MANAGER_INTERFACE: &str = "org.freedesktop.login1.Manager";
const SESSION_INTERFACE: &str = "org.freedesktop.login1.Session";
const DBUS: &str = "org.freedesktop.DBus";

pub(super) struct ObserverGuard {
    acknowledgement: Arc<Acknowledgement>,
    shutdown: Option<oneshot::Sender<()>>,
    worker: Option<JoinHandle<()>>,
}

impl ObserverGuard {
    pub(super) fn acknowledge(&self, token: Option<u64>) {
        self.acknowledgement.acknowledge(token);
    }
}

impl Drop for ObserverGuard {
    fn drop(&mut self) {
        self.acknowledgement.stop();
        if let Some(shutdown) = self.shutdown.take() {
            let _sent = shutdown.send(());
        }
        if let Some(worker) = self.worker.take() {
            let _joined = worker.join();
        }
    }
}

pub(super) async fn start(failed: FailureCallback) -> io::Result<SessionObserver> {
    let (sink, receiver) = event_stream(failed);
    let acknowledgement = Arc::clone(&sink.acknowledgement);
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let (ready_tx, ready_rx) = oneshot::channel();
    let worker = std::thread::Builder::new().name("locket-logind".to_owned()).spawn(move || {
        match tokio::runtime::Builder::new_current_thread().enable_all().build() {
            Ok(runtime) => runtime.block_on(run(sink, shutdown_rx, ready_tx)),
            Err(error) => {
                let _sent = ready_tx.send(Err(error));
            }
        }
    })?;
    let guard =
        ObserverGuard { acknowledgement, shutdown: Some(shutdown_tx), worker: Some(worker) };
    ready_rx.await.map_err(|_| io::Error::other("Linux session observer startup stopped"))??;
    Ok(SessionObserver { receiver, guard, backend_name: "Linux logind session notifications" })
}

async fn run(
    sink: EventSink,
    mut shutdown: oneshot::Receiver<()>,
    ready: oneshot::Sender<io::Result<()>>,
) {
    let setup = tokio::select! {
        _ = &mut shutdown => return,
        result = tokio::time::timeout(Duration::from_secs(5), LogindObserver::new()) => {
            result.unwrap_or_else(|_| Err(io::Error::new(io::ErrorKind::TimedOut, "logind setup timed out")))
        }
    };
    let mut observer = match setup {
        Ok(observer) => observer,
        Err(error) => {
            let _sent = ready.send(Err(error));
            return;
        }
    };
    if !sink.emit(screen_event(observer.initially_locked)) {
        return;
    }
    if ready.send(Ok(())).is_err() {
        return;
    }
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            _ = observer.ownership.next() => {
                // Any logind ownership change invalidates the subscription and
                // inhibitor. Even a restart with the same public name is fatal.
                sink.fail();
                break;
            }
            message = observer.signals.next() => {
                let Some(Ok(message)) = message else { sink.fail(); break };
                let handling = tokio::time::timeout(Duration::from_secs(2), observer.handle(&message, &sink));
                tokio::select! {
                    _ = &mut shutdown => break,
                    result = handling => {
                        if !matches!(result, Ok(Ok(()))) { sink.fail(); break; }
                    }
                }
            }
        }
    }
}

struct LogindObserver {
    manager: Proxy<'static>,
    session: Proxy<'static>,
    session_path: String,
    signals: MessageStream,
    ownership: MessageStream,
    inhibitor: Option<OwnedFd>,
    acknowledgement_timeout: Duration,
    initially_locked: bool,
}

impl LogindObserver {
    async fn new() -> io::Result<Self> {
        let connection =
            zbus::connection::Builder::address("unix:path=/run/dbus/system_bus_socket")
                .build()
                .await
                .map_err(dbus_error)?;
        let dbus = Proxy::new(&connection, DBUS, "/org/freedesktop/DBus", DBUS)
            .await
            .map_err(dbus_error)?;
        // Subscribe before resolving ownership so a restart during setup cannot
        // silently leave a live-looking observer bound to an obsolete daemon.
        let owner_rule = MatchRule::builder()
            .msg_type(Type::Signal)
            .sender(DBUS)
            .interface(DBUS)
            .member("NameOwnerChanged")
            .add_arg(SERVICE)
            .build()
            .map_err(dbus_error)?;
        let ownership =
            MessageStream::for_match_rule(owner_rule, &connection, NonZeroUsize::new(8))
                .await
                .map_err(dbus_error)?;
        let owner: String = dbus.call("GetNameOwner", &SERVICE).await.map_err(dbus_error)?;
        let owner_uid: u32 =
            dbus.call("GetConnectionUnixUser", &owner).await.map_err(dbus_error)?;
        if owner_uid != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "logind bus owner is not root",
            ));
        }
        let rule = MatchRule::builder()
            .msg_type(Type::Signal)
            .sender(owner.clone())
            .build()
            .map_err(dbus_error)?;
        let signals = MessageStream::for_match_rule(rule, &connection, NonZeroUsize::new(64))
            .await
            .map_err(dbus_error)?;
        let manager =
            uncached_proxy(&connection, owner.clone(), MANAGER_PATH.to_owned(), MANAGER_INTERFACE)
                .await?;
        let path: OwnedObjectPath =
            manager.call("GetSessionByPID", &std::process::id()).await.map_err(dbus_error)?;
        let session_path = path.as_str().to_owned();
        let session =
            uncached_proxy(&connection, owner.clone(), session_path.clone(), SESSION_INTERFACE)
                .await?;
        let session_type: String = session.get_property("Type").await.map_err(dbus_error)?;
        if !matches!(session_type.as_str(), "wayland" | "x11") {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "logind monitoring requires a graphical user session",
            ));
        }
        let delay_us: u64 =
            manager.get_property("InhibitDelayMaxUSec").await.map_err(dbus_error)?;
        let acknowledgement_timeout = suspend_budget(delay_us)?;
        let inhibitor = Some(inhibit(&manager).await?);
        let initially_locked = session_locked(&session).await?;
        if manager.get_property::<bool>("PreparingForSleep").await.map_err(dbus_error)? {
            return Err(io::Error::other("cannot start session monitoring during suspend"));
        }
        let current_owner: String =
            dbus.call("GetNameOwner", &SERVICE).await.map_err(dbus_error)?;
        if current_owner != owner {
            return Err(io::Error::other("logind restarted during observer startup"));
        }
        Ok(Self {
            manager,
            session,
            session_path,
            signals,
            ownership,
            inhibitor,
            acknowledgement_timeout,
            initially_locked,
        })
    }

    async fn handle(&mut self, message: &Message, sink: &EventSink) -> io::Result<()> {
        let header = message.header();
        let path = header.path().map(zbus::ObjectPath::as_str);
        let interface = header.interface().map(zbus::names::InterfaceName::as_str);
        let member = header.member().map(zbus::names::MemberName::as_str);
        if path == Some(MANAGER_PATH) && interface == Some(MANAGER_INTERFACE) {
            match member {
                Some("PrepareForSleep") => {
                    let sleeping: bool = message.body().deserialize().map_err(dbus_error)?;
                    if sleeping {
                        // Keep the delay inhibitor alive until the agent has
                        // erased keys/revoked grants, or the fail-closed callback
                        // has terminated the daemon before logind's deadline.
                        if !sink.suspend(self.acknowledgement_timeout) {
                            return Err(io::Error::other("suspend erasure was not acknowledged"));
                        }
                        self.inhibitor = None;
                    } else {
                        self.inhibitor = Some(inhibit(&self.manager).await?);
                        sink.emit(screen_event(session_locked(&self.session).await?));
                        sink.emit(NativeSessionEvent::SystemWake);
                    }
                }
                Some("SessionRemoved") => {
                    let DynamicTuple((_id, removed)): DynamicTuple<(String, OwnedObjectPath)> =
                        message.body().deserialize().map_err(dbus_error)?;
                    if removed.as_str() == self.session_path {
                        return Err(io::Error::other("monitored logind session was removed"));
                    }
                }
                _ => {}
            }
        } else if path == Some(self.session_path.as_str()) {
            if interface == Some(SESSION_INTERFACE) {
                match member {
                    Some("Lock") => {
                        sink.emit(NativeSessionEvent::ScreenLock);
                    }
                    Some("Unlock") => {
                        sink.emit(screen_event(session_locked(&self.session).await?));
                    }
                    _ => {}
                }
            } else if interface == Some("org.freedesktop.DBus.Properties")
                && member == Some("PropertiesChanged")
            {
                let DynamicTuple((changed_interface, changed, invalidated)): DynamicTuple<(
                    String,
                    HashMap<String, OwnedVariant>,
                    Vec<String>,
                )> = message.body().deserialize().map_err(dbus_error)?;
                if changed_interface == SESSION_INTERFACE
                    && ["LockedHint", "Active"].iter().any(|key| {
                        changed.contains_key(*key) || invalidated.iter().any(|name| name == key)
                    })
                {
                    sink.emit(screen_event(session_locked(&self.session).await?));
                }
            }
        }
        Ok(())
    }
}

async fn uncached_proxy(
    connection: &Connection,
    owner: String,
    path: String,
    interface: &'static str,
) -> io::Result<Proxy<'static>> {
    zbus::proxy::Builder::new(connection)
        .destination(owner)
        .path(path)
        .interface(interface)
        .cache_properties(CacheProperties::No)
        .build()
        .await
        .map_err(dbus_error)
}

async fn session_locked(session: &Proxy<'_>) -> io::Result<bool> {
    let locked: bool = session.get_property("LockedHint").await.map_err(dbus_error)?;
    let active: bool = session.get_property("Active").await.map_err(dbus_error)?;
    Ok(locked || !active)
}

async fn inhibit(manager: &Proxy<'_>) -> io::Result<OwnedFd> {
    manager
        .call(
            "Inhibit",
            &DynamicTuple(("sleep", "Locket", "Erase unlocked keys before suspend", "delay")),
        )
        .await
        .map_err(dbus_error)
}

const fn screen_event(locked: bool) -> NativeSessionEvent {
    if locked { NativeSessionEvent::ScreenLock } else { NativeSessionEvent::ScreenUnlock }
}

fn suspend_budget(delay_us: u64) -> io::Result<Duration> {
    if delay_us < 100_000 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "logind suspend delay is too short for secure key erasure",
        ));
    }
    // Leave half of the configured inhibitor deadline for scheduling jitter;
    // the cap also stays below the per-signal D-Bus handling deadline.
    Ok(Duration::from_micros((delay_us / 2).min(1_000_000)))
}

fn dbus_error(error: zbus::Error) -> io::Error {
    io::Error::other(error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logind_suspend_budget_respects_native_deadline() {
        assert!(suspend_budget(99_999).is_err());
        assert_eq!(suspend_budget(100_000).ok(), Some(Duration::from_millis(50)));
        assert_eq!(suspend_budget(1_000_000).ok(), Some(Duration::from_millis(500)));
        assert_eq!(suspend_budget(u64::MAX).ok(), Some(Duration::from_secs(1)));
    }
}
