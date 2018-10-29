// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::malice::MaliceEvent;
use super::Environment;
use super::Observation;
use super::{PeerStatus, PeerStatuses};
#[cfg(feature = "dump-graphs")]
use dump_graph::DIR;
use mock::{PeerId, Transaction, NAMES};
use observation::Observation as ParsecObservation;
use rand::Rng;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
#[cfg(feature = "dump-graphs")]
use std::fs::File;
#[cfg(feature = "dump-graphs")]
use std::io::Write;
use std::iter;
use std::mem;

/// This struct holds the data necessary to make a simulated request when a node executes a local
/// step.
#[derive(Clone, Debug)]
pub struct Request {
    /// The recipient of the request - it will then respond back to the sender
    pub recipient: PeerId,
    /// The delay, in steps, between sending and reception of the request
    pub req_delay: usize,
    /// The delay, in steps, between sending and reception of the response
    pub resp_delay: usize,
}

/// Describes whether the node should make a request during its local step
#[derive(Clone, Debug)]
pub enum RequestTiming {
    /// Don't make a request
    Later,
    /// Make a request
    DuringThisStep(Request),
}

/// Represents an event the network is supposed to simulate.
/// The simulation proceeds in steps. During every global step, every node has some probability
/// of being scheduled to perform a local step, consisting of receiving messages that reached it
/// by this time, generating appropriate responses and optionally sending a gossip request.
#[derive(Clone, Debug)]
pub enum ScheduleEvent {
    /// Event storing the names of the initial nodes
    Genesis(BTreeSet<PeerId>),
    /// This event variant represents a node being scheduled to execute a local step. It contains a
    /// global step number, the ID of the node being scheduled, and optionally data of the request
    /// the node will send.
    LocalStep {
        global_step: usize,
        peer: PeerId,
        request_timing: RequestTiming,
    },
    /// This event causes the node with the given ID to stop responding. All further events
    /// concerning that node will be ignored.
    Fail(PeerId),
    /// This event makes a node vote on the given observation.
    VoteFor(PeerId, Observation),
    /// Adds a honest peer to the network (this is separate from nodes voting to add the peer)
    AddHonestPeer(PeerId),
    /// Adds a malicious peer to the network with the given malice schedule.
    AddMaliciousPeer(PeerId, Vec<(usize, MaliceEvent)>),
    /// Removes a peer from the network (this is separate from nodes voting to remove the peer)
    /// It is similar to Fail in that the peer will stop responding; however, this will also
    /// cause the other peers to vote for removal
    RemovePeer(PeerId),
}

// A function generating a Poisson-distributed random number.
fn poisson<R: Rng>(rng: &mut R, lambda: f64) -> usize {
    let mut result = 0;
    let mut p = 1.0;
    let l = (-lambda).exp();
    loop {
        p *= rng.gen::<f64>();
        if p <= l {
            break;
        }
        result += 1;
    }
    result
}

impl ScheduleEvent {
    fn gen_request<R: Rng>(
        rng: &mut R,
        peer: &PeerId,
        peers: &[PeerId],
        options: &ScheduleOptions,
    ) -> Request {
        let mut recipient = peer;
        while recipient == peer {
            recipient = unwrap!(rng.choose(peers));
        }
        let req_delay = options.gen_delay(rng);
        let resp_delay = options.gen_delay(rng);
        Request {
            recipient: recipient.clone(),
            req_delay,
            resp_delay,
        }
    }

    pub fn gen_local_step<R: Rng>(
        rng: &mut R,
        step: usize,
        peer: &PeerId,
        peers: &[PeerId],
        options: &ScheduleOptions,
    ) -> ScheduleEvent {
        let request_timing = if rng.gen::<f64>() < options.gossip_prob {
            RequestTiming::DuringThisStep(Self::gen_request(rng, peer, peers, options))
        } else {
            RequestTiming::Later
        };
        ScheduleEvent::LocalStep {
            global_step: step,
            peer: peer.clone(),
            request_timing,
        }
    }

    pub fn fail(&self) -> Option<&PeerId> {
        if let ScheduleEvent::Fail(ref peer) = self {
            Some(peer)
        } else {
            None
        }
    }

    pub fn get_peer(&self) -> &PeerId {
        match *self {
            ScheduleEvent::LocalStep { ref peer, .. } => peer,
            ScheduleEvent::Fail(ref peer) => peer,
            ScheduleEvent::VoteFor(ref peer, _) => peer,
            ScheduleEvent::AddHonestPeer(ref peer) => peer,
            ScheduleEvent::AddMaliciousPeer(ref peer, _) => peer,
            ScheduleEvent::RemovePeer(ref peer) => peer,
            ScheduleEvent::Genesis(_) => panic!("ScheduleEvent::get_peer called on Genesis!"),
        }
    }
}

fn binomial<R: Rng>(rng: &mut R, n: usize, p: f64) -> usize {
    let mut successes = 0;
    for _ in 0..n {
        if rng.gen::<f64>() < p {
            successes += 1;
        }
    }
    successes
}

/// Stores pending observations per node, so that nodes only vote for each observation once.
pub struct PendingObservations {
    min_delay: usize,
    max_delay: usize,
    p_delay: f64,
    queues: BTreeMap<PeerId, BTreeMap<usize, Vec<Observation>>>,
}

impl PendingObservations {
    pub fn new(opts: &ScheduleOptions) -> PendingObservations {
        PendingObservations {
            min_delay: opts.min_observation_delay,
            max_delay: opts.max_observation_delay,
            p_delay: opts.p_observation_delay,
            queues: BTreeMap::new(),
        }
    }

    /// Add the observation to peers' queues at a random step after the event happened
    pub fn peers_make_observation<'a, R: Rng, I: Iterator<Item = &'a PeerId>>(
        &mut self,
        rng: &mut R,
        peers: I,
        step: usize,
        observation: &Observation,
    ) {
        for peer in peers {
            let observations = self
                .queues
                .entry(peer.clone())
                .or_insert_with(BTreeMap::new);
            let tgt_step = step
                + self.min_delay
                + binomial(rng, self.max_delay - self.min_delay, self.p_delay);
            let step_observations = observations.entry(tgt_step).or_insert_with(Vec::new);
            step_observations.push(observation.clone());
        }
    }

    /// Pops all the observations that should be made at `step` at the latest
    pub fn pop_at_step(&mut self, peer: &PeerId, step: usize) -> Vec<Observation> {
        let mut result = vec![];
        if let Some(queue) = self.queues.get_mut(peer) {
            let to_leave = queue.split_off(&(step + 1));
            let popped = mem::replace(queue, to_leave);
            for (_, observations) in popped {
                result.extend(observations.into_iter());
            }
            result
        } else {
            vec![]
        }
    }

    /// Returns true if no more peers have pending observations
    pub fn queues_empty<'a, I: Iterator<Item = &'a PeerId>>(&self, mut peers: I) -> bool {
        peers.all(|id| self.queues.get(id).map_or(true, |queue| queue.is_empty()))
    }
}

/// Available options for the distribution of message delays
#[derive(Clone, Copy, Debug)]
pub enum DelayDistribution {
    Poisson(f64),
    Constant(usize),
}

/// A struct aggregating the options controlling schedule generation
#[derive(Clone, Debug)]
pub struct ScheduleOptions {
    /// Size of the genesis group
    pub genesis_size: usize,
    /// Probability per global step that a node will be scheduled to execute a local step
    pub prob_local_step: f64,
    /// Probabilitity per step that a random node will fail
    pub prob_failure: f64,
    /// Probability that a vote will get repeated
    pub prob_vote_duplication: f64,
    /// A map: step number → num of nodes to fail
    pub deterministic_failures: BTreeMap<usize, usize>,
    /// The distribution of message delays
    pub delay_distr: DelayDistribution,
    /// The probability that a node will gossip during its local step
    pub gossip_prob: f64,
    /// When true, nodes will first insert all votes into the graph, then start gossiping
    pub votes_before_gossip: bool,
    /// Number of opaque observations to make
    pub opaque_to_add: usize,
    /// Probability per global step that a node will make a vote
    pub prob_opaque: f64,
    /// The number of peers to be added during the simulation
    pub peers_to_add: usize,
    /// Probability per step that a peer will get added
    pub prob_add: f64,
    /// The number of peers to be removed during the simulation
    pub peers_to_remove: usize,
    /// Probability per step that a peer will get removed
    pub prob_remove: f64,
    /// Minimum number of non-failed peers
    pub min_peers: usize,
    /// Maximum number of peers
    pub max_peers: usize,
    /// Minimum delay between an event and its observation
    pub min_observation_delay: usize,
    /// Maximum delay between an event and its observation
    pub max_observation_delay: usize,
    /// The binomial distribution p coefficient for observation delay
    pub p_observation_delay: f64,
}

impl ScheduleOptions {
    /// Generates a delay according to the delay distribution
    pub fn gen_delay<R: Rng>(&self, rng: &mut R) -> usize {
        match self.delay_distr {
            DelayDistribution::Poisson(lambda) => poisson(rng, lambda),
            DelayDistribution::Constant(x) => x,
        }
    }
}

impl Default for ScheduleOptions {
    fn default() -> ScheduleOptions {
        ScheduleOptions {
            // default genesis of 4 peers
            genesis_size: 4,
            // local step on average every 6-7 steps - not too often
            prob_local_step: 0.15,
            // no randomised failures
            prob_failure: 0.0,
            // no vote duplication
            prob_vote_duplication: 0.0,
            // no deterministic failures
            deterministic_failures: BTreeMap::new(),
            // randomised delays, 4 steps on average
            delay_distr: DelayDistribution::Poisson(4.0),
            // gossip every other local step
            gossip_prob: 0.5,
            // vote while gossiping
            votes_before_gossip: false,
            // add 5 opaque observations
            opaque_to_add: 5,
            // vote for an opaque observation every ~20 steps
            prob_opaque: 0.05,
            // no adds
            peers_to_add: 0,
            // add a node every 50 steps, on average
            prob_add: 0.02,
            // no removes
            peers_to_remove: 0,
            // remove a node every 50 steps, on average
            prob_remove: 0.02,
            // always keep at least 3 active peers
            min_peers: 3,
            // allow at most as many peers as we have names
            max_peers: NAMES.len(),
            // observation delay between 1
            min_observation_delay: 1,
            // ...and 100
            max_observation_delay: 100,
            // with binomial p coefficient 0.45
            p_observation_delay: 0.45,
        }
    }
}

pub enum ObservationEvent {
    Opaque(Transaction),
    AddPeer(PeerId),
    RemovePeer(PeerId),
    Fail(PeerId),
}

impl ObservationEvent {
    pub fn is_opaque(&self) -> bool {
        match *self {
            ObservationEvent::Opaque(_) => true,
            _ => false,
        }
    }

    pub fn get_opaque(self) -> Option<Observation> {
        match self {
            ObservationEvent::Opaque(t) => Some(ParsecObservation::OpaquePayload(t)),
            _ => None,
        }
    }
}

pub struct ObservationSchedule {
    pub genesis: BTreeSet<PeerId>,
    /// A `Vec` of pairs (step number, event), carrying information about what events happen at
    /// which steps
    pub schedule: Vec<(usize, ObservationEvent)>,
}

impl ObservationSchedule {
    fn gen<R: Rng>(
        rng: &mut R,
        mut genesis_names: BTreeSet<PeerId>,
        options: &ScheduleOptions,
    ) -> ObservationSchedule {
        let mut schedule = vec![];
        let mut names_iter = NAMES.iter();

        // a counter for peer adds/removes and opaque transactions
        // (so not counting genesis and failures)
        let mut num_observations: usize = 0;
        let mut added_peers: usize = 0;
        let mut removed_peers: usize = 0;
        let mut opaque_count: usize = 0;

        // schedule genesis first
        if genesis_names.is_empty() {
            genesis_names.extend(
                names_iter
                    .by_ref()
                    .take(options.genesis_size)
                    .map(|s| PeerId::new(*s)),
            )
        }
        let mut peers = PeerStatuses::new(&genesis_names);

        let mut step: usize = 1;
        while num_observations
            < options.opaque_to_add + options.peers_to_add + options.peers_to_remove
        {
            if opaque_count < options.opaque_to_add && rng.gen::<f64>() < options.prob_opaque {
                schedule.push((step, ObservationEvent::Opaque(rng.gen())));
                num_observations += 1;
                opaque_count += 1;
            }
            if added_peers < options.peers_to_add && rng.gen::<f64>() < options.prob_add {
                let next_id = PeerId::new(names_iter.next().unwrap());
                peers.add_peer(next_id.clone());
                schedule.push((step, ObservationEvent::AddPeer(next_id)));
                num_observations += 1;
                added_peers += 1;
            }
            if removed_peers < options.peers_to_remove && rng.gen::<f64>() < options.prob_remove {
                if let Some(id) = peers.remove_random_peer(rng, options.min_peers) {
                    schedule.push((step, ObservationEvent::RemovePeer(id)));
                    num_observations += 1;
                    removed_peers += 1;
                }
            }

            // generate a random failure
            if rng.gen::<f64>() < options.prob_failure {
                if let Some(id) = peers.fail_random_peer(rng, options.min_peers) {
                    schedule.push((step, ObservationEvent::Fail(id)));
                }
            }
            // then handle deterministic failures
            let num_deterministic_fails = options
                .deterministic_failures
                .get(&step)
                .cloned()
                .unwrap_or(0);

            for _ in 0..num_deterministic_fails {
                if let Some(id) = peers.fail_random_peer(rng, options.min_peers) {
                    schedule.push((step, ObservationEvent::Fail(id)));
                }
            }

            step += 1;
        }

        ObservationSchedule {
            genesis: genesis_names,
            schedule,
        }
    }

    fn extract_opaque(&mut self) -> Vec<Observation> {
        let schedule = mem::replace(&mut self.schedule, vec![]);
        let (opaque, rest): (Vec<_>, _) = schedule
            .into_iter()
            .partition(|&(_, ref observation)| observation.is_opaque());
        self.schedule = rest;
        opaque
            .into_iter()
            .filter_map(|(_, o)| o.get_opaque())
            .collect()
    }

    fn for_step(&mut self, step: usize) -> Vec<ObservationEvent> {
        let schedule = mem::replace(&mut self.schedule, vec![]);
        let (current, rest): (Vec<_>, _) = schedule
            .into_iter()
            .partition(|&(scheduled_step, _)| scheduled_step <= step);
        let current = current.into_iter().map(|(_, obs)| obs).collect();
        self.schedule = rest;
        current
    }

    fn count_observations(&self) -> usize {
        self.schedule
            .iter()
            .filter(|&(_, ref event)| match *event {
                ObservationEvent::Fail(_) => false,
                _ => true,
            }).count()
    }
}

/// Stores the list of network events to be simulated.
#[derive(Clone)]
pub struct Schedule {
    pub peers: BTreeMap<PeerId, PeerStatus>,
    pub num_observations: usize,
    pub events: Vec<ScheduleEvent>,
}

impl fmt::Debug for Schedule {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "----------------------------")?;
        writeln!(f, " Schedule:")?;
        for event in &self.events {
            writeln!(f, "- {:?}", event)?;
        }
        writeln!(f, "----------------------------")
    }
}

impl Schedule {
    pub fn build(env: &mut Environment) -> ScheduleBuilder {
        ScheduleBuilder {
            env,
            options: None,
            genesis: BTreeSet::new(),
            obs_schedule: Vec::new(),
            malice_schedule: BTreeMap::new(),
        }
    }

    #[cfg(feature = "dump-graphs")]
    fn save(&self, options: &ScheduleOptions) {
        let path = DIR.with(|dir| dir.join("schedule.txt"));
        if let Ok(mut file) = File::create(&path) {
            unwrap!(writeln!(
                file,
                "Generating a schedule with options: {:?}",
                options
            ));
            unwrap!(write!(file, "{:?}", self));
        } else {
            println!("Failed to create {:?}", path);
        }
    }

    fn perform_step<R: Rng>(
        rng: &mut R,
        step: usize,
        peers: &mut PeerStatuses,
        // mut required to be able to use the inner reference in a loop
        mut pending: Option<&mut PendingObservations>,
        schedule: &mut Vec<ScheduleEvent>,
        options: &ScheduleOptions,
    ) {
        // first, peers that get scheduled make observations and perform local steps
        for peer in peers.active_peers() {
            if rng.gen::<f64>() < options.prob_local_step {
                // we do a local step for peer
                // first, they need to make observations
                if let Some(pending) = pending.as_mut() {
                    for observation in pending.pop_at_step(peer, step) {
                        schedule.push(ScheduleEvent::VoteFor(peer.clone(), observation));
                    }
                }
                let present_peers: Vec<_> = peers.present_peers().cloned().collect();
                schedule.push(ScheduleEvent::gen_local_step(
                    rng,
                    step,
                    peer,
                    &present_peers,
                    options,
                ));
            }
        }
    }
}

pub struct ScheduleBuilder<'a, 'b> {
    env: &'a mut Environment,
    options: Option<&'b ScheduleOptions>,
    genesis: BTreeSet<PeerId>,
    obs_schedule: Vec<(usize, ObservationEvent)>,
    malice_schedule: BTreeMap<PeerId, Vec<(usize, MaliceEvent)>>,
}

impl<'a, 'b> ScheduleBuilder<'a, 'b> {
    pub fn with_options(mut self, options: &'b ScheduleOptions) -> Self {
        self.options = Some(options);
        self
    }

    pub fn with_observation_schedule(
        mut self,
        genesis_names: BTreeSet<PeerId>,
        schedule: Vec<(usize, ObservationEvent)>,
    ) -> Self {
        self.genesis = genesis_names;
        self.obs_schedule = schedule;
        self
    }

    pub fn with_malice_schedule(
        mut self,
        peer_id: PeerId,
        mut schedule: Vec<(usize, MaliceEvent)>,
    ) -> Self {
        self.malice_schedule
            .entry(peer_id)
            .or_insert_with(Vec::new)
            .append(&mut schedule);
        self
    }

    /// The `let_and_return` clippy lint is allowed since it is actually necessary to create the
    /// `result` variable so the result can be saved when the `dump-graphs` feature is used.
    #[cfg_attr(feature = "cargo-clippy", allow(let_and_return))]
    pub fn finish(self) -> Schedule {
        let rng = &mut self.env.rng;

        let default_options = ScheduleOptions::default();
        let options = self.options.unwrap_or(&default_options);

        let mut obs_schedule = if self.obs_schedule.is_empty() {
            ObservationSchedule::gen(rng, self.genesis, options)
        } else {
            ObservationSchedule {
                genesis: self.genesis,
                schedule: self.obs_schedule,
            }
        };

        let mut malice_schedule = self.malice_schedule;

        let mut pending = PendingObservations::new(options);
        // the +1 below is to account for genesis
        let num_observations = obs_schedule.count_observations() + 1;

        let mut peers = PeerStatuses::new(&obs_schedule.genesis);
        let mut step = 0;

        // genesis has to be first
        let mut schedule = vec![ScheduleEvent::Genesis(obs_schedule.genesis.clone())];
        let mut observations_made = vec![];

        // if votes before gossip enabled, insert all votes
        if options.votes_before_gossip {
            let opaque_transactions = obs_schedule.extract_opaque();
            for obs in opaque_transactions {
                pending.peers_make_observation(rng, peers.active_peers(), step, &obs);
                observations_made.push(obs);
            }
        }

        while !obs_schedule.schedule.is_empty() || !pending.queues_empty(peers.active_peers()) {
            let obs_for_step = obs_schedule.for_step(step);
            for observation in obs_for_step {
                match observation {
                    ObservationEvent::AddPeer(new_peer) => {
                        peers.add_peer(new_peer.clone());
                        pending.peers_make_observation(
                            rng,
                            peers.active_peers(),
                            step,
                            &ParsecObservation::Add(new_peer.clone()),
                        );

                        if let Some(malice_schedule) = malice_schedule.remove(&new_peer) {
                            schedule.push(ScheduleEvent::AddMaliciousPeer(
                                new_peer.clone(),
                                malice_schedule,
                            ));
                        } else {
                            schedule.push(ScheduleEvent::AddHonestPeer(new_peer.clone()));
                        }

                        // vote for all observations that were made before this peer joined
                        // this prevents situations in which peers joining reach consensus before
                        // some other observations they haven't seen, which cause those
                        // observations to no longer have a supermajority of votes and never get
                        // consensused; this is something that can validly happen in a real
                        // network, but causes problems with evaluating test results
                        for obs in &observations_made {
                            pending.peers_make_observation(rng, iter::once(&new_peer), step, obs);
                        }
                    }
                    ObservationEvent::RemovePeer(peer) => {
                        peers.remove_peer(&peer);
                        pending.peers_make_observation(
                            rng,
                            peers.active_peers(),
                            step,
                            &ParsecObservation::Remove(peer.clone()),
                        );
                        schedule.push(ScheduleEvent::RemovePeer(peer));
                    }
                    ObservationEvent::Opaque(payload) => {
                        let observation = ParsecObservation::OpaquePayload(payload);
                        pending.peers_make_observation(
                            rng,
                            peers.active_peers(),
                            step,
                            &observation,
                        );
                        observations_made.push(observation);
                    }
                    ObservationEvent::Fail(peer) => {
                        peers.fail_peer(&peer);
                        schedule.push(ScheduleEvent::Fail(peer));
                    }
                }
            }
            Schedule::perform_step(
                rng,
                step,
                &mut peers,
                Some(&mut pending),
                &mut schedule,
                options,
            );
            step += 1;
        }

        let n = peers.present_peers().count() as f64;
        // Gossip should theoretically complete in O(log N) steps
        // But the number of local steps taken by each node depends on the probability
        // of a local step - each node will take on avg [num steps]*[prob] local steps
        // Thus, we divide log N by the probability.
        // The constant (adjustment_coeff) is for making the number big enough.
        let adjustment_coeff = 200.0;
        let additional_steps = (adjustment_coeff * n.ln() / options.prob_local_step) as usize;
        for _ in 0..additional_steps {
            Schedule::perform_step(rng, step, &mut peers, None, &mut schedule, options);
            step += 1;
        }

        let result = Schedule {
            peers: peers.into(),
            num_observations,
            events: schedule,
        };
        #[cfg(feature = "dump-graphs")]
        result.save(options);
        result
    }
}
