//! The support-session worker. It starts only in a build made with `live_support` and the
//! exact activation marker; ordinary builds run local checks only.
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};

use diagnostics::remote_policy::RemotePolicy;
use diagnostics::site;
use diagnostics::support_client::FriendClient;

/// True only with `live_support`, the activation marker and a support pair in `site.toml`.
pub fn remote_enabled() -> bool {
    cfg!(feature = "live_support")
        && option_env!("FRIEND_SUPPORT_ACTIVATED") == Some("reviewed-activation")
        && site::SUPPORT.is_some()
}

pub enum RemoteEvent {
    Started(String),
    Paired,
    Retrying,
    Recovered,
    Activity(String),
    Ended(String),
}

pub struct RemoteLink {
    pub events: mpsc::Receiver<RemoteEvent>,
    pub stop: Arc<AtomicBool>,
    pub pause: Arc<AtomicBool>,
    pub cancel_current: Arc<AtomicBool>,
    pub consent: Arc<AtomicBool>,
    pub worker: Option<thread::JoinHandle<()>>,
}

pub fn spawn_remote() -> RemoteLink {
    let (sender, events) = mpsc::channel();
    let stop = Arc::new(AtomicBool::new(false));
    let pause = Arc::new(AtomicBool::new(false));
    let cancel_current = Arc::new(AtomicBool::new(false));
    let consent = Arc::new(AtomicBool::new(true));
    let worker_stop = stop.clone();
    let worker_pause = pause.clone();
    let worker_cancel = cancel_current.clone();
    let worker_consent = consent.clone();
    let worker = thread::spawn(move || {
        let Some(support) = site::SUPPORT.as_ref() else {
            let _ = sender.send(RemoteEvent::Ended("Support connection unavailable".into()));
            return;
        };
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(value) => value,
            Err(_) => {
                let _ = sender.send(RemoteEvent::Ended("Connection could not start".into()));
                return;
            }
        };
        runtime.block_on(async move {
            let (client, code) = match FriendClient::start(
                support.endpoint,
                support.operator_email,
                worker_consent.clone(),
                worker_cancel.clone(),
                worker_stop.clone(),
            )
            .await
            {
                Ok(value) => value,
                Err(_) => {
                    let _ =
                        sender.send(RemoteEvent::Ended("Support connection unavailable".into()));
                    return;
                }
            };
            let _ = sender.send(RemoteEvent::Started(code));
            let mut paired = false;
            let mut policy = RemotePolicy::new(Instant::now(), Duration::from_secs(300));
            let mut ending = "Support session ended";
            while !worker_stop.load(Ordering::SeqCst)
                && worker_consent.load(Ordering::SeqCst)
                && !policy.expired(Instant::now())
            {
                if worker_pause.load(Ordering::SeqCst) {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    continue;
                }
                worker_cancel.store(false, Ordering::SeqCst);
                let cycle = match client.poll().await {
                    Ok(status) => {
                        if status.operator.as_deref() == Some(support.operator_email) && !paired {
                            paired = true;
                            let _ = sender.send(RemoteEvent::Paired);
                        }
                        if status.command.is_some() {
                            // The client records command, arguments, duration and outcome.
                            let result = client.execute_one().await;
                            if let Ok(Some(executed)) = &result {
                                let _ = sender.send(RemoteEvent::Activity(executed.line()));
                            }
                            result.map(|_| ())
                        } else {
                            Ok(())
                        }
                    }
                    Err(error) => Err(error),
                };
                if worker_stop.load(Ordering::SeqCst) {
                    break;
                }
                if worker_pause.load(Ordering::SeqCst) {
                    continue;
                }
                match cycle {
                    Ok(()) => {
                        if policy.success() {
                            let _ = sender.send(RemoteEvent::Recovered);
                        }
                    }
                    Err(_) => {
                        let Some(delay) = policy.failure() else {
                            ending = "Connection lost; checks stopped";
                            break;
                        };
                        let _ = sender.send(RemoteEvent::Retrying);
                        tokio::time::sleep(delay).await;
                    }
                }
                tokio::time::sleep(Duration::from_millis(400)).await;
            }
            if policy.expired(Instant::now()) {
                ending = "Session expired";
            }
            worker_stop.store(true, Ordering::SeqCst);
            worker_cancel.store(true, Ordering::SeqCst);
            worker_consent.store(false, Ordering::SeqCst);
            let _ = client.disconnect().await;
            let _ = sender.send(RemoteEvent::Ended(ending.into()));
        });
    });
    RemoteLink {
        events,
        stop,
        pause,
        cancel_current,
        consent,
        worker: Some(worker),
    }
}
