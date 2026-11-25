//! Where a client's Groth16 proofs run, and whether circuit artifacts stay loaded between them.
//!
//! A proof's parallel work, key parsing included, runs on the Rayon pool current where the proof
//! is made. [`ProvingConfig`] picks that pool: by default one the client builds for its proofs
//! alone, so a proof never queues behind, or ahead of, the host's own work on the global pool.

use std::sync::{Arc, Mutex, PoisonError};

use anyhow::{Context, Result};
use curvy_witnesscalc::ArtifactCache;

/// Prefix of the names of the threads in a client's own proving pool.
pub const PROVER_THREAD_NAME: &str = "curvy-prover";

/// How a [`CurvyClient`](crate::CurvyClient) runs its Groth16 proofs.
///
/// The default runs proofs on a pool of [`ProvingConfig::default_threads`] threads that the
/// client builds on its first proof, and keeps each circuit's witness graph and proving key
/// loaded after its first proof.
///
/// Each client has its own pool and its own loaded circuits: clients in one process share
/// neither unless they are given the same pool with [`Self::thread_pool`].
#[derive(Clone)]
pub struct ProvingConfig {
    threads: Threads,
    keep_loaded: bool,
}

#[derive(Clone)]
enum Threads {
    /// A pool of this many threads, built by the client on its first proof.
    Own(usize),
    /// A pool the host built.
    Host(Arc<rayon::ThreadPool>),
    /// The process's global Rayon pool.
    Global,
}

impl ProvingConfig {
    pub fn new() -> Self {
        Self::default()
    }

    /// Half the available CPUs, at least one: the size of the client's own pool unless
    /// [`Self::threads`] sets another.
    pub fn default_threads() -> usize {
        std::thread::available_parallelism().map_or(1, |cpus| (cpus.get() / 2).max(1))
    }

    /// Run proofs on a pool of `threads` threads, at least one, that the client builds on its
    /// first proof. Its threads are named `curvy-prover-<index>`.
    pub fn threads(mut self, threads: usize) -> Self {
        self.threads = Threads::Own(threads.max(1));
        self
    }

    /// Run proofs on `pool`. A host that wants the proving threads at a lower scheduling
    /// priority, or pinned to some CPUs, builds the pool with a `start_handler` that does so.
    pub fn thread_pool(mut self, pool: Arc<rayon::ThreadPool>) -> Self {
        self.threads = Threads::Host(pool);
        self
    }

    /// Run proofs on the process's global Rayon pool, shared with everything else that uses it.
    pub fn global_pool(mut self) -> Self {
        self.threads = Threads::Global;
        self
    }

    /// Keep each circuit's witness graph and proving key in memory after its first proof
    /// (`true`, the default), or load and authenticate both for every proof (`false`).
    ///
    /// A kept circuit takes about 1.4 times the size of its zkey file in memory: 131 MiB for the
    /// PIX withdrawal.
    pub fn keep_loaded(mut self, keep: bool) -> Self {
        self.keep_loaded = keep;
        self
    }
}

impl Default for ProvingConfig {
    fn default() -> Self {
        Self {
            threads: Threads::Own(Self::default_threads()),
            keep_loaded: true,
        }
    }
}

/// A client's proving state: its configuration, its own pool once built, and its loaded
/// circuits.
pub(crate) struct Proving {
    threads: Threads,
    own_pool: Mutex<Option<Arc<rayon::ThreadPool>>>,
    cache: Option<ArtifactCache>,
}

impl Proving {
    pub(crate) fn new(config: ProvingConfig) -> Self {
        Self {
            threads: config.threads,
            own_pool: Mutex::new(None),
            cache: config.keep_loaded.then(ArtifactCache::new),
        }
    }

    /// The pool proofs run on, building the client's own on first use. `None` is the global
    /// pool.
    fn pool(&self) -> Result<Option<Arc<rayon::ThreadPool>>> {
        match &self.threads {
            Threads::Global => Ok(None),
            Threads::Host(pool) => Ok(Some(Arc::clone(pool))),
            Threads::Own(threads) => {
                let mut own = self.own_pool.lock().unwrap_or_else(PoisonError::into_inner);
                if let Some(pool) = own.as_ref() {
                    return Ok(Some(Arc::clone(pool)));
                }
                let pool = Arc::new(
                    rayon::ThreadPoolBuilder::new()
                        .num_threads(*threads)
                        .thread_name(|index| format!("{PROVER_THREAD_NAME}-{index}"))
                        .build()
                        .context("build the proving thread pool")?,
                );
                *own = Some(Arc::clone(&pool));
                Ok(Some(pool))
            }
        }
    }

    /// Run `job` on a blocking worker, inside the proving pool, with the artifact cache it proves
    /// from: the client's when it keeps circuits loaded, else one dropped after the job.
    pub(crate) async fn run<T, F>(self: &Arc<Self>, what: &'static str, job: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&ArtifactCache) -> Result<T> + Send + 'static,
    {
        let proving = Arc::clone(self);
        tokio::task::spawn_blocking(move || {
            let scratch;
            let cache = match &proving.cache {
                Some(cache) => cache,
                None => {
                    scratch = ArtifactCache::new();
                    &scratch
                }
            };
            match proving.pool()? {
                Some(pool) => pool.install(|| job(cache)),
                None => job(cache),
            }
        })
        .await
        .with_context(|| format!("join {what} proof"))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The size of the pool a job runs on and the name of its thread.
    async fn placement(proving: &Arc<Proving>) -> (usize, Option<String>) {
        proving
            .run("test", |_| {
                Ok((
                    rayon::current_num_threads(),
                    std::thread::current().name().map(str::to_owned),
                ))
            })
            .await
            .unwrap()
    }

    fn is_own_thread(name: &Option<String>) -> bool {
        name.as_deref()
            .is_some_and(|name| name.starts_with(PROVER_THREAD_NAME))
    }

    #[tokio::test]
    async fn proofs_run_on_the_clients_own_pool_by_default() {
        let proving = Arc::new(Proving::new(ProvingConfig::new().threads(3)));
        let (threads, name) = placement(&proving).await;
        assert_eq!(threads, 3);
        assert!(is_own_thread(&name), "{name:?}");
    }

    #[tokio::test]
    async fn the_own_pool_is_built_once() {
        let proving = Arc::new(Proving::new(ProvingConfig::new().threads(2)));
        placement(&proving).await;
        let first = proving.pool().unwrap().unwrap();
        placement(&proving).await;
        assert!(Arc::ptr_eq(&first, &proving.pool().unwrap().unwrap()));
    }

    #[tokio::test]
    async fn parallel_work_inside_a_proof_stays_on_the_proving_pool() {
        let proving = Arc::new(Proving::new(ProvingConfig::new().threads(2)));
        let names = proving
            .run("test", |_| {
                use rayon::prelude::*;
                Ok((0..64)
                    .into_par_iter()
                    .map(|_| std::thread::current().name().map(str::to_owned))
                    .collect::<Vec<_>>())
            })
            .await
            .unwrap();
        assert!(names.iter().all(is_own_thread), "{names:?}");
    }

    #[tokio::test]
    async fn a_host_pool_is_used_as_given() {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(2)
            .thread_name(|index| format!("host-{index}"))
            .build()
            .unwrap();
        let proving = Arc::new(Proving::new(
            ProvingConfig::new().thread_pool(Arc::new(pool)),
        ));
        let (threads, name) = placement(&proving).await;
        assert_eq!(threads, 2);
        assert!(
            name.as_deref()
                .is_some_and(|name| name.starts_with("host-"))
        );
    }

    #[tokio::test]
    async fn the_global_pool_is_shared() {
        let proving = Arc::new(Proving::new(ProvingConfig::new().global_pool()));
        let (threads, name) = placement(&proving).await;
        assert_eq!(threads, rayon::current_num_threads());
        assert!(!is_own_thread(&name), "{name:?}");
    }

    #[test]
    fn keeping_artifacts_loaded_is_the_default_and_can_be_turned_off() {
        assert!(Proving::new(ProvingConfig::new()).cache.is_some());
        assert!(
            Proving::new(ProvingConfig::new().keep_loaded(false))
                .cache
                .is_none()
        );
    }

    #[test]
    fn a_pool_has_at_least_one_thread() {
        assert!(ProvingConfig::default_threads() >= 1);
        assert!(matches!(
            ProvingConfig::new().threads(0).threads,
            Threads::Own(1)
        ));
    }
}
