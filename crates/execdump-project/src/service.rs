/*
 * Background decompilation: worker threads decompile every function of a program, the ones shown
 * on screen first. Each worker owns a decompiler (they are not thread safe, and keep the signatures
 * they discovered); the names and prototypes given by the user are broadcast to all of them before
 * the functions they affect are queued again.
 */

use crate::annotations::FunctionNotes;
use crate::cache::{Cache, Meta, Rendered};

use execdump_core::crash;
use execdump_core::program::Program;
use execdump_decompiler::analysis::Analysis;
use execdump_decompiler::c::ast::CFunction;
use execdump_decompiler::notes::{apply_summary, apply_vars, used_names};
use execdump_decompiler::types::Prototype;
use execdump_decompiler::{Decompiler, SharedSignatures};

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, VecDeque};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Condvar, Mutex};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Priority {
    /// Everything else, in the order the functions were queued (callees first)
    Background = 0,
    /// Callees and callers of what is shown
    Near = 1,
    /// Shown on screen
    Visible = 2,
}

#[derive(Clone, Debug)]
pub enum Control {
    Rename(u64, Option<String>),
    Prototype(u64, Option<Prototype>),
}

#[derive(Clone, Debug)]
pub enum Event {
    Decompiled { addr: u64, fingerprint: u64 },
    /// One-off decompilation with other notes (proposals), not cached
    Preview { id: u64, addr: u64, rendered: Rendered },
}

struct Pending {
    fingerprint: u64,
    notes: Arc<FunctionNotes>,
    priority: Priority,
}

struct Preview {
    id: u64,
    addr: u64,
    notes: FunctionNotes,
    name: Option<String>,
}

#[derive(Default)]
struct Queue {
    pending: HashMap<u64, Pending>,
    heap: BinaryHeap<(Priority, Reverse<u64>, u64)>,
    previews: VecDeque<Preview>,
    seq: u64,
    running: usize,
    shutdown: bool,
}

enum Job {
    Render { addr: u64, fingerprint: u64, notes: Arc<FunctionNotes> },
    Preview(Preview),
}

struct Shared {
    queue: Mutex<Queue>,
    ready: Condvar,
    controls: Vec<Mutex<Vec<(u64, Control)>>>,
    signatures: SharedSignatures,
}

impl Shared {
    fn next(&self) -> Option<Job> {
        let mut queue = self.queue.lock().unwrap();

        loop {
            if queue.shutdown {
                return None;
            }

            if let Some(preview) = queue.previews.pop_front() {
                queue.running += 1;
                return Some(Job::Preview(preview));
            }

            // Entries whose priority changed since they were pushed are stale
            while let Some((priority, _, addr)) = queue.heap.pop() {
                if queue.pending.get(&addr).is_some_and(|p| p.priority == priority) {
                    let pending = queue.pending.remove(&addr).unwrap();
                    queue.running += 1;
                    return Some(Job::Render { addr, fingerprint: pending.fingerprint, notes: pending.notes });
                }
            }

            queue = self.ready.wait(queue).unwrap();
        }
    }

    fn finished(&self) {
        self.queue.lock().unwrap().running -= 1;
    }
}

pub struct Service {
    shared: Arc<Shared>,
    cache: Arc<Mutex<Cache>>,
    events: Receiver<Event>,
}

impl Service {
    pub fn start(program: Arc<Program>, analysis: Arc<Analysis>, cache: Cache, workers: usize) -> Self {
        let workers = workers.max(1);
        let shared = Arc::new(Shared {
            queue: Mutex::new(Queue::default()),
            ready: Condvar::new(),
            controls: (0..workers).map(|_| Mutex::new(Vec::new())).collect(),
            signatures: SharedSignatures::default(),
        });
        let cache = Arc::new(Mutex::new(cache));
        let (sender, events) = channel();

        for index in 0..workers {
            let (shared, cache, sender) = (shared.clone(), cache.clone(), sender.clone());
            let (program, analysis) = (program.clone(), analysis.clone());

            crash::thread(&format!("decompiler-{}", index))
                .spawn(move || worker(index, &program, &analysis, &shared, &cache, &sender))
                .expect("cannot start a decompilation thread");
        }

        return Service { shared, cache, events };
    }

    pub fn cache(&self) -> &Arc<Mutex<Cache>> {
        return &self.cache;
    }

    /// Queues a function (replaces its queued version)
    pub fn enqueue(&self, addr: u64, fingerprint: u64, notes: Arc<FunctionNotes>, priority: Priority) {
        let mut queue = self.shared.queue.lock().unwrap();
        let priority = queue.pending.get(&addr).map_or(priority, |p| p.priority.max(priority));
        let seq = queue.seq;

        queue.seq += 1;
        queue.pending.insert(addr, Pending { fingerprint, notes, priority });
        queue.heap.push((priority, Reverse(seq), addr));

        drop(queue);
        self.shared.ready.notify_one();
    }

    /// Raises the priority of queued functions
    pub fn prioritize(&self, addrs: &[u64], priority: Priority) {
        let mut queue = self.shared.queue.lock().unwrap();

        for &addr in addrs {
            let raised = match queue.pending.get_mut(&addr) {
                Some(pending) if pending.priority < priority => {
                    pending.priority = priority;
                    true
                }
                _ => false,
            };

            if raised {
                // Shown functions are taken in the order they are asked for, the latest first
                let seq = u64::MAX - queue.seq;
                queue.seq += 1;
                queue.heap.push((priority, Reverse(seq), addr));
            }
        }
    }

    /// Changes what the decompilers know (names, prototypes), before the functions using it are queued again
    pub fn control(&self, control: Control) {
        // Signatures discovered with the previous annotations are not shared anymore
        let epoch = self.shared.signatures.invalidate();

        for controls in self.shared.controls.iter() {
            controls.lock().unwrap().push((epoch, control.clone()));
        }
    }

    pub fn preview(&self, id: u64, addr: u64, notes: FunctionNotes, name: Option<String>) {
        self.shared.queue.lock().unwrap().previews.push_back(Preview { id, addr, notes, name });
        self.shared.ready.notify_one();
    }

    pub fn poll(&self) -> Vec<Event> {
        return self.events.try_iter().collect();
    }

    /// Blocks until an event arrives (or the timeout)
    pub fn wait(&self, timeout: std::time::Duration) -> Option<Event> {
        return self.events.recv_timeout(timeout).ok();
    }

    /// Functions waiting to be decompiled, and being decompiled
    pub fn pending(&self) -> (usize, usize) {
        let queue = self.shared.queue.lock().unwrap();
        return (queue.pending.len() + queue.previews.len(), queue.running);
    }

    pub fn is_idle(&self) -> bool {
        return self.pending() == (0, 0);
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        // Workers in the middle of a function finish it and stop
        self.shared.queue.lock().unwrap().shutdown = true;
        self.shared.ready.notify_all();
    }
}

fn worker(index: usize, program: &Program, analysis: &Analysis, shared: &Shared, cache: &Mutex<Cache>, events: &Sender<Event>) {
    let create = || Decompiler::new(program, analysis).map(|d| d.with_shared_signatures(shared.signatures.clone()));
    let mut decompiler = create();
    // Everything the decompiler was told, for the one replacing it after a panic
    let mut controls: Vec<(u64, Control)> = Vec::new();

    while let Some(job) = shared.next() {
        // Controls are sent before the jobs they affect are queued: drained after taking the job
        let received = std::mem::take(&mut *shared.controls[index].lock().unwrap());

        if let Ok(decompiler) = decompiler.as_ref() {
            apply(decompiler, &received);
        }

        controls.extend(received);

        let (addr, notes, name) = match &job {
            Job::Render { addr, notes, .. } => (*addr, &**notes, None),
            Job::Preview(preview) => (preview.addr, &preview.notes, preview.name.as_deref()),
        };

        let rendered = match crash::catch(|| render(decompiler.as_ref(), addr, notes, name)) {
            Ok(rendered) => rendered,
            Err(error) => {
                // What the decompiler was doing is left half done
                decompiler = create();

                if let Ok(decompiler) = decompiler.as_ref() {
                    apply(decompiler, &controls);
                }

                let name = analysis.functions.get(&addr).map_or_else(|| format!("sub_{:x}", addr), |f| f.name.clone());
                failed(addr, &name, &error)
            }
        };

        let event = match job {
            Job::Render { addr, fingerprint, .. } => {
                cache.lock().unwrap().put(addr, fingerprint, rendered);
                Event::Decompiled { addr, fingerprint }
            }
            Job::Preview(preview) => Event::Preview { id: preview.id, addr: preview.addr, rendered },
        };

        shared.finished();

        if events.send(event).is_err() {
            return;
        }
    }
}

fn apply(decompiler: &Decompiler, controls: &[(u64, Control)]) {
    for (epoch, control) in controls {
        match control {
            Control::Rename(addr, name) => decompiler.rename(*addr, name.clone()),
            Control::Prototype(addr, prototype) => decompiler.set_prototype(*addr, prototype.clone()),
        }

        decompiler.set_epoch(*epoch);
    }
}

/// C code of a function with the notes of the user applied
pub fn render(decompiler: Result<&Decompiler, &String>, addr: u64, notes: &FunctionNotes, name: Option<&str>) -> Rendered {
    let decompiler = match decompiler {
        Ok(decompiler) => decompiler,
        Err(error) => return failed(addr, &format!("sub_{:x}", addr), error),
    };

    return match decompiler.c_function(addr) {
        Ok(function) => render_function(decompiler, function, notes, name),
        Err(error) => failed(addr, &decompiler.function_name(addr), &error),
    };
}

/// Text of a decompiled function with the notes applied
pub fn render_function(decompiler: &Decompiler, mut function: CFunction, notes: &FunctionNotes, name: Option<&str>) -> Rendered {
    let original: Vec<String> = function.vars.iter().map(|v| v.name.clone()).collect();
    let errors = apply_vars(&mut function, &notes.var_notes(), &decompiler.typedb);

    if let Some(summary) = notes.summary.as_deref() {
        apply_summary(&mut function, summary);
    }

    if let Some(name) = name {
        function.name = name.to_string();
    }

    let printed = function.print();
    let used = used_names(&function);
    let mut meta = Meta { signature: function.signature(), errors, ..Meta::default() };

    meta.vars = original.into_iter().zip(function.vars.iter().map(|v| v.name.clone())).collect();

    for name in used.calls.iter().chain(used.others.iter()) {
        if let Some(prototype) = decompiler.prototype(name) {
            meta.decls.push(format!("{};", prototype));
        } else if let Some(addr) = decompiler.global_address(name) {
            meta.globals.push((name.clone(), addr));
        }
    }

    meta.calls = used.calls.into_iter().collect();
    meta.others = used.others.into_iter().collect();

    return Rendered { ok: true, text: printed.text, lines: printed.lines, meta };
}

fn failed(addr: u64, name: &str, error: &str) -> Rendered {
    let text = format!("// {} ({:#x}): decompilation failed: {}\n", name, addr, error.replace('\n', " "));
    return Rendered { ok: false, text, lines: vec![Some(addr)], meta: Meta { signature: name.to_string(), ..Meta::default() } };
}
