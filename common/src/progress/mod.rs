//! Progress reporting

use std::future::Future;

pub mod indicatif;

pub trait Progress: Send + Sync {
    type Instance: ProgressBar;

    fn start(&self, work: usize) -> Self::Instance;

    fn println(&self, #[allow(unused_variables)] message: &str) {}
}

pub trait ProgressBar: Send {
    fn tick(&mut self) -> impl Future<Output = ()> + Send {
        self.increment(1)
    }

    fn increment(&mut self, work: usize) -> impl Future<Output = ()> + Send;

    fn finish(self) -> impl Future<Output = ()> + Send;

    fn set_message(&mut self, msg: String) -> impl Future<Output = ()> + Send;
}

impl Progress for () {
    type Instance = ();

    fn start(&self, _work: usize) -> Self::Instance {}

    fn println(&self, message: &str) {
        println!("{message}");
    }
}

pub struct NoOpIter<I>(I)
where
    I: Iterator;

impl<I> Iterator for NoOpIter<I>
where
    I: Iterator,
{
    type Item = I::Item;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }
}

impl ProgressBar for () {
    async fn increment(&mut self, _work: usize) {}

    async fn finish(self) {}

    async fn set_message(&mut self, _msg: String) {}
}

impl<P: Progress> Progress for Option<P> {
    type Instance = Option<P::Instance>;

    fn start(&self, work: usize) -> Self::Instance {
        self.as_ref().map(|progress| progress.start(work))
    }

    fn println(&self, message: &str) {
        if let Some(progress) = self {
            progress.println(message)
        } else {
            println!("{message}");
        }
    }
}

impl<P: ProgressBar> ProgressBar for Option<P> {
    async fn increment(&mut self, work: usize) {
        if let Some(bar) = self {
            bar.increment(work).await;
        }
    }

    async fn finish(self) {
        if let Some(bar) = self {
            bar.finish().await;
        }
    }

    async fn set_message(&mut self, msg: String) {
        if let Some(bar) = self {
            bar.set_message(msg).await;
        }
    }
}
