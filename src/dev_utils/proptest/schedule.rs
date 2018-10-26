// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{Bounded, BoundedBoxedStrategy};
use dev_utils::environment::{Environment, RngChoice};
use dev_utils::schedule::{DelayDistribution, Schedule, ScheduleOptions};
use proptest_crate::prelude::{Just, RngCore};
use proptest_crate::strategy::{NewTree, Strategy, ValueTree};
use proptest_crate::test_runner::TestRunner;

#[derive(Debug)]
pub struct ScheduleOptionsStrategy {
    pub num_peers: BoundedBoxedStrategy<usize>,
    pub num_observations: BoundedBoxedStrategy<usize>,
    pub local_step: BoundedBoxedStrategy<f64>,
    pub recv_trans: BoundedBoxedStrategy<f64>,
    pub failure: BoundedBoxedStrategy<f64>,
    pub vote_duplication: BoundedBoxedStrategy<f64>,
    pub delay_distr: BoundedBoxedStrategy<DelayDistribution>,
}

#[allow(unused)]
pub fn const_delay<T>(distr: T) -> BoundedBoxedStrategy<DelayDistribution>
where
    T: Strategy<Value = usize> + Bounded<Bound = usize> + 'static,
{
    let min = DelayDistribution::Constant(distr.min());
    let max = DelayDistribution::Constant(distr.max());
    let boxed_str = distr.prop_map(DelayDistribution::Constant).boxed();
    BoundedBoxedStrategy::from_boxed(boxed_str, min, max)
}

#[allow(unused)]
pub fn poisson_delay<T>(distr: T) -> BoundedBoxedStrategy<DelayDistribution>
where
    T: Strategy<Value = f64> + Bounded<Bound = f64> + 'static,
{
    let min = DelayDistribution::Poisson(distr.min());
    let max = DelayDistribution::Poisson(distr.max());
    let boxed_str = distr.prop_map(DelayDistribution::Poisson).boxed();
    BoundedBoxedStrategy::from_boxed(boxed_str, min, max)
}

#[allow(unused)]
pub fn arbitrary_delay<T, U>(cnst: T, poisson: U) -> BoundedBoxedStrategy<DelayDistribution>
where
    T: Strategy<Value = usize> + Bounded<Bound = usize> + 'static,
    U: Strategy<Value = f64> + Bounded<Bound = f64> + 'static,
{
    let min = DelayDistribution::Constant(cnst.min());
    let max = DelayDistribution::Poisson(poisson.max());
    let boxed_str = prop_oneof![
        cnst.prop_map(DelayDistribution::Constant),
        poisson.prop_map(DelayDistribution::Poisson),
    ].boxed();
    BoundedBoxedStrategy::from_boxed(boxed_str, min, max)
}

impl Default for ScheduleOptionsStrategy {
    fn default() -> ScheduleOptionsStrategy {
        ScheduleOptionsStrategy {
            num_peers: Just(6).into(),
            num_observations: Just(1).into(),
            local_step: Just(0.15).into(),
            recv_trans: Just(0.05).into(),
            failure: Just(0.0).into(),
            vote_duplication: Just(0.0).into(),
            delay_distr: Just(DelayDistribution::Poisson(4.0)).into(),
        }
    }
}

impl Strategy for ScheduleOptionsStrategy {
    type Value = ScheduleOptions;
    type Tree = ScheduleOptionsValueTree;

    fn new_tree(&self, runner: &mut TestRunner) -> NewTree<Self> {
        let max_sched = ScheduleOptions {
            genesis_size: self.num_peers.max(),
            opaque_to_add: self.num_observations.max(),
            prob_local_step: self.local_step.min(),
            prob_opaque: self.recv_trans.max(),
            prob_failure: self.failure.max(),
            prob_vote_duplication: self.vote_duplication.max(),
            delay_distr: self.delay_distr.max(),
            ..Default::default()
        };
        let min_sched = ScheduleOptions {
            genesis_size: self.num_peers.min(),
            opaque_to_add: self.num_observations.min(),
            prob_local_step: self.local_step.max(),
            prob_opaque: self.recv_trans.min(),
            prob_failure: self.failure.min(),
            prob_vote_duplication: self.vote_duplication.min(),
            delay_distr: self.delay_distr.min(),
            ..Default::default()
        };
        // order is important here - the default implementation bisects the first value first, then
        // switches to the next, and the next - so the values should be sorted in a rough order of
        // "importance"
        let (l_min, l_max) = (self.local_step.min(), self.local_step.max());
        (
            &self.num_peers,
            &self.num_observations,
            &self.failure,
            &self.vote_duplication,
            &self.recv_trans,
            (&self.local_step).prop_map(move |l| l_max + l_min - l),
            &self.delay_distr,
        )
            .prop_map(|(np, no, f, v, r, l, d)| ScheduleOptions {
                genesis_size: np,
                opaque_to_add: no,
                prob_failure: f,
                prob_vote_duplication: v,
                prob_opaque: r,
                prob_local_step: l,
                delay_distr: d,
                ..Default::default()
            }).new_tree(runner)
            .map(|t| ScheduleOptionsValueTree {
                max_sched,
                min_sched,
                generator: Box::new(t),
            })
    }
}

/// This struct is a wrapper around a mapped value tree that lets us implement Bounded
pub struct ScheduleOptionsValueTree {
    max_sched: ScheduleOptions,
    min_sched: ScheduleOptions,
    generator: Box<ValueTree<Value = ScheduleOptions>>,
}

impl Bounded for ScheduleOptionsValueTree {
    type Bound = ScheduleOptions;

    fn min(&self) -> ScheduleOptions {
        self.min_sched.clone()
    }

    fn max(&self) -> ScheduleOptions {
        self.max_sched.clone()
    }
}

impl ValueTree for ScheduleOptionsValueTree {
    type Value = ScheduleOptions;

    fn current(&self) -> ScheduleOptions {
        self.generator.current()
    }

    fn simplify(&mut self) -> bool {
        self.generator.simplify()
    }

    fn complicate(&mut self) -> bool {
        self.generator.complicate()
    }
}

#[derive(Debug, Default)]
pub struct ScheduleStrategy {
    pub opts: ScheduleOptionsStrategy,
}

impl Strategy for ScheduleStrategy {
    type Value = (Environment, Schedule);
    type Tree = ScheduleValueTree;

    fn new_tree(&self, runner: &mut TestRunner) -> NewTree<Self> {
        let seed = {
            let rng = runner.rng();
            [
                rng.next_u32(),
                rng.next_u32(),
                rng.next_u32(),
                rng.next_u32(),
            ]
        };
        self.opts
            .new_tree(runner)
            .and_then(|o| Ok(ScheduleValueTree::new(seed, o)))
    }
}

pub struct ScheduleValueTree {
    seed: [u32; 4],
    opts: ScheduleOptionsValueTree,
    #[allow(unused)]
    max_schedule: Schedule,
}

impl ScheduleValueTree {
    pub fn new(seed: [u32; 4], opts: ScheduleOptionsValueTree) -> Self {
        let mut env = Environment::new(RngChoice::SeededXor(seed));
        let max_opts = opts.max();
        let max_schedule = Schedule::build(&mut env).with_options(&max_opts).finish();
        ScheduleValueTree {
            seed,
            opts,
            max_schedule,
        }
    }
}

impl ScheduleValueTree {
    fn filtered_schedule(&self, opts: &ScheduleOptions) -> (Environment, Schedule) {
        // TODO: implement actual filtering of the max schedule
        let mut env = Environment::new(RngChoice::SeededXor(self.seed));
        let schedule = Schedule::build(&mut env).with_options(opts).finish();
        (env, schedule)
    }
}

impl ValueTree for ScheduleValueTree {
    type Value = (Environment, Schedule);

    fn current(&self) -> (Environment, Schedule) {
        let cur_opts = self.opts.current();
        trace!("Scheduling with options: {:?}", cur_opts);
        let (env, schedule) = self.filtered_schedule(&cur_opts);
        trace!("{:?}", schedule);
        (env, schedule)
    }

    fn simplify(&mut self) -> bool {
        self.opts.simplify()
    }

    fn complicate(&mut self) -> bool {
        self.opts.complicate()
    }
}
