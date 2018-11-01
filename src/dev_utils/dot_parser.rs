// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use gossip::Event;
use hash::Hash;
use meta_voting::{BoolSet, MetaElectionHandle, MetaEvent, MetaVote, Step};
use mock::{PeerId, Transaction};
use observation::Observation;
use peer_list::{PeerList, PeerState};
use pom::char_class::{self, *};
use pom::parser::*;
use pom::Result as PomResult;
use pom::{DataInput, Parser};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::thread;

fn next_line() -> Parser<u8, ()> {
    none_of(b"\r\n").repeat(0..) * one_of(b"\r\n").discard()
}

fn multispace() -> Parser<u8, ()> {
    is_a(char_class::multispace).repeat(0..).discard()
}

#[derive(Debug)]
struct ParsedFile {
    our_id: PeerId,
    peer_states: BTreeMap<PeerId, PeerState>,
    details: BTreeMap<String, EventDetails>,
    graph: BTreeMap<String, ParsedEvent>,
    meta_votes: BTreeMap<String, ParsedMetaVotes>,
}

fn parse_file() -> Parser<u8, ParsedFile> {
    (next_line().repeat(3) * parse_our_id()
        + parse_peer_states()
        + parse_event_details()
        + parse_graph()
        + parse_meta_votes()
        - parse_footer()).map(|((((oid, pstates), details), graph), mv)| ParsedFile {
        our_id: oid,
        peer_states: pstates,
        details,
        graph,
        meta_votes: mv,
    })
}

fn parse_peer_id() -> Parser<u8, PeerId> {
    is_a(alphanum)
        .repeat(1..)
        .collect()
        .convert(String::from_utf8)
        .map(|s| PeerId::new(&s))
}

fn parse_our_id() -> Parser<u8, PeerId> {
    seq(b"/// our_id: ") * parse_peer_id() - multispace()
}

fn parse_peer_states() -> Parser<u8, BTreeMap<PeerId, PeerState>> {
    let list_defs = seq(b"/// peer_states: {") * list(
        parse_peer_id() - seq(b": \"") + parse_peer_state() - sym(b'"'),
        seq(b", "),
    ) - sym(b'}') * multispace();
    list_defs.map(|defs| defs.into_iter().collect())
}

fn parse_peer_state() -> Parser<u8, PeerState> {
    let state = seq(b"PeerState(") * list(parse_single_state(), sym(b'|')) - sym(b')');
    state.map(|states| {
        states
            .into_iter()
            .fold(PeerState::inactive(), |s1, s2| s1 | s2)
    })
}

fn parse_single_state() -> Parser<u8, PeerState> {
    seq(b"VOTE").map(|_| PeerState::VOTE)
        | seq(b"SEND").map(|_| PeerState::SEND)
        | seq(b"RECV").map(|_| PeerState::RECV)
}

fn parse_peers() -> Parser<u8, BTreeSet<PeerId>> {
    (sym(b'{') * list(parse_peer_id(), seq(b", ")) - sym(b'}')).map(|v| v.into_iter().collect())
}

fn parse_event_details() -> Parser<u8, BTreeMap<String, EventDetails>> {
    parse_single_event_detail()
        .repeat(1..)
        .map(|details| details.into_iter().collect())
}

#[derive(Debug)]
struct EventDetails {
    cause: String,
    interesting_content: Vec<Observation<Transaction, PeerId>>,
    last_ancestors: BTreeMap<PeerId, u64>,
}

fn parse_single_event_detail() -> Parser<u8, (String, EventDetails)> {
    (parse_id_line() + parse_cause() + parse_interesting_content() + parse_last_ancestors()
        - next_line()).map(|(((id, cause), interesting_content), last_ancestors)| {
        (
            id,
            EventDetails {
                cause,
                interesting_content,
                last_ancestors,
            },
        )
    })
}

fn parse_id_line() -> Parser<u8, String> {
    seq(b"/// { ") * parse_event_id() - next_line()
}

fn parse_event_id() -> Parser<u8, String> {
    (is_a(hex_digit).repeat(6..) - seq(b"..")).convert(String::from_utf8)
}

fn parse_cause() -> Parser<u8, String> {
    (seq(b"/// cause: ") * none_of(b"\r\n").repeat(1..) - one_of(b"\r\n").repeat(1..))
        .convert(String::from_utf8)
}

fn parse_interesting_content() -> Parser<u8, Vec<Observation<Transaction, PeerId>>> {
    seq(b"/// interesting_content: [") * list(parse_observation(), seq(b", "))
        - sym(b']')
        - next_line()
}

fn parse_observation() -> Parser<u8, Observation<Transaction, PeerId>> {
    parse_genesis() | parse_add() | parse_remove() | parse_opaque()
}

fn parse_genesis() -> Parser<u8, Observation<Transaction, PeerId>> {
    (seq(b"Genesis(") * parse_peers() - seq(b")")).map(Observation::Genesis)
}

fn parse_add() -> Parser<u8, Observation<Transaction, PeerId>> {
    (seq(b"Add(") * parse_peer_id() - seq(b")")).map(Observation::Add)
}

fn parse_remove() -> Parser<u8, Observation<Transaction, PeerId>> {
    (seq(b"Remove(") * parse_peer_id() - seq(b")")).map(Observation::Remove)
}

fn parse_opaque() -> Parser<u8, Observation<Transaction, PeerId>> {
    (seq(b"OpaquePayload(") * parse_transaction() - seq(b")"))
        .map(|s| Transaction::new(&s))
        .map(Observation::OpaquePayload)
}

fn parse_transaction() -> Parser<u8, String> {
    is_a(alphanum).repeat(1..).convert(String::from_utf8)
}

fn parse_last_ancestors() -> Parser<u8, BTreeMap<PeerId, u64>> {
    (seq(b"/// last_ancestors: {") * list(
        parse_peer_id() - seq(b": ") + is_a(digit)
            .repeat(1..)
            .convert(String::from_utf8)
            .convert(|s| u64::from_str(&s)),
        seq(b", "),
    ) - next_line()).map(|v| v.into_iter().collect())
}

#[derive(Debug)]
struct ParsedEvent {
    creator: PeerId,
    self_parent: Option<String>,
    other_parent: Option<String>,
}

fn parse_graph() -> Parser<u8, BTreeMap<String, ParsedEvent>> {
    parse_subgraph().repeat(1..).map(|graphs| {
        let mut graph = BTreeMap::new();
        for subgraph in graphs {
            let mut self_parent = None;
            for event in subgraph.events {
                let other_parent = subgraph.other_parents.get(&event).cloned();
                let _ = graph.insert(
                    event.clone(),
                    ParsedEvent {
                        creator: subgraph.creator.clone(),
                        self_parent: self_parent.clone(),
                        other_parent,
                    },
                );
                self_parent = Some(event);
            }
        }
        graph
    })
}

#[derive(Debug)]
struct ParsedEdge {
    start: String,
    end: String,
}

#[derive(Debug)]
struct ParsedSubgraph {
    creator: PeerId,
    events: Vec<String>,
    other_parents: BTreeMap<String, String>,
}

fn parse_subgraph() -> Parser<u8, ParsedSubgraph> {
    let id = next_line() * multispace() * seq(b"subgraph cluster_") * parse_peer_id()
        - next_line().repeat(3);
    let data =
        id + parse_first_edge() + parse_edge().repeat(0..) - multispace() - sym(b'}') - next_line()
            + parse_edge().repeat(0..)
            - next_line();
    // edges1 will contain the creator's line - we are only interested in the set of events at the
    // end of edges
    data.map(|(((id, first_edge), edges1), edges2)| ParsedSubgraph {
        creator: id,
        events: {
            let mut events = vec![first_edge];
            events.extend(edges1.into_iter().map(|edge| edge.end));
            events
        },
        other_parents: edges2
            .into_iter()
            .map(|edge| (edge.end, edge.start))
            .collect(),
    })
}

fn parse_first_edge() -> Parser<u8, String> {
    multispace() * parse_peer_id() * seq(b" -> \"") * parse_event_id() - next_line()
}

fn parse_edge() -> Parser<u8, ParsedEdge> {
    (multispace() * sym(b'"') * parse_event_id() - seq(b"\" -> \"") + parse_event_id()
        - next_line()).map(|(id1, id2)| ParsedEdge {
        start: id1,
        end: id2,
    })
}

type ParsedMetaVotes = BTreeMap<PeerId, Vec<MetaVote>>;

fn parse_meta_votes() -> Parser<u8, BTreeMap<String, ParsedMetaVotes>> {
    seq(b"/// meta-vote section") * next_line() * parse_event_entry().repeat(1..).map(|v| {
        v.into_iter()
            .filter_map(|(id, opt_mv)| opt_mv.map(|mv| (id, mv)))
            .collect()
    })
}

fn parse_event_entry() -> Parser<u8, (String, Option<ParsedMetaVotes>)> {
    (multispace() * sym(b'"').name("start event id") * parse_event_id()
        - sym(b'"').name("end event id")
        - multispace()
        - sym(b'[')
        - none_of(b"\"]").repeat(0..)
        + parse_label().opt()
        - sym(b']')
        - next_line())
}

fn parse_label() -> Parser<u8, ParsedMetaVotes> {
    let interesting_content =
        sym(b'[') * none_of(b"]").repeat(1..) * sym(b']') * next_line().discard();
    sym(b'"').name("start label")
        * ((next_line()
            * (parse_observation() * next_line()).opt()
            * interesting_content.opt()
            * (parse_peer_meta_votes() - one_of(b"\r\n")).repeat(0..)
            + parse_peer_meta_votes()).map(|(mut mvs_vec, mvs)| {
            mvs_vec.push(mvs);
            mvs_vec
                .into_iter()
                .map(|(peer_initial, votes)| {
                    (PeerId::from_initial(char::from(peer_initial)), votes)
                }).collect()
        }) | none_of(b"\"").repeat(0..).map(|_| BTreeMap::new()))
        - sym(b'"').name("end label")
}

fn parse_peer_meta_votes() -> Parser<u8, (u8, Vec<MetaVote>)> {
    is_a(alphanum) - sym(b':') - multispace() - sym(b'[') - multispace()
        + list(parse_meta_vote(), one_of(b"\r\n").repeat(1..))
        - multispace()
        - sym(b']')
}

fn parse_meta_vote() -> Parser<u8, MetaVote> {
    (sym(b'{') * multispace() * parse_number() - sym(b'/') + parse_number() - seq(b", est:")
        + parse_bool_set()
        - seq(b" bin:")
        + parse_bool_set()
        - seq(b" aux:")
        + parse_opt_bool()
        - seq(b" dec:")
        + parse_opt_bool()
        - seq(b" }")).map(|(((((round, step), est), bin), aux), dec)| MetaVote {
        round: round as usize,
        step: match step {
            0 => Step::ForcedTrue,
            1 => Step::ForcedFalse,
            2 => Step::GenuineFlip,
            _ => unreachable!(),
        },
        estimates: est,
        bin_values: bin,
        aux_value: aux,
        decision: dec,
    })
}

fn parse_number() -> Parser<u8, u64> {
    is_a(digit)
        .repeat(1..)
        .convert(String::from_utf8)
        .convert(|s| u64::from_str(&s))
}

fn parse_bool() -> Parser<u8, bool> {
    sym(b't').map(|_| true) | sym(b'f').map(|_| false)
}

fn parse_bool_set() -> Parser<u8, BoolSet> {
    (sym(b'{') * list(parse_bool(), seq(b", ")) - sym(b'}')).map(|v| {
        v.into_iter().fold(BoolSet::default(), |mut bs, v| {
            let _ = bs.insert(v);
            bs
        })
    })
}

fn parse_opt_bool() -> Parser<u8, Option<bool>> {
    sym(b'{') * parse_bool().opt() - sym(b'}')
}

fn parse_footer() -> Parser<u8, ()> {
    // check that it's actually the end
    one_of(b" \r\n").repeat(2..).discard()
        - sym(b'{')
        - (none_of(b"}").repeat(0..) * sym(b'}')).repeat(2)
        - multispace()
        - end()
}

/// The event graph and associated info that were parsed from the dumped dot file.
pub(crate) struct ParsedContents {
    pub our_id: PeerId,
    pub events: BTreeMap<Hash, Event<Transaction, PeerId>>,
    pub meta_events: BTreeMap<Hash, MetaEvent<Transaction, PeerId>>,
    pub peer_list: PeerList<PeerId>,
}

impl ParsedContents {
    /// Create empty `ParsedContents`.
    pub fn new(our_id: PeerId) -> Self {
        let peer_list = PeerList::new(our_id.clone());

        ParsedContents {
            our_id,
            events: BTreeMap::new(),
            meta_events: BTreeMap::new(),
            peer_list,
        }
    }

    /// Remove and return the latest (newest) event from the `ParsedContents`, if any.
    pub fn remove_latest_event(&mut self) -> Option<Event<Transaction, PeerId>> {
        let hash = *self
            .events
            .values()
            .max_by_key(|event| event.order())
            .map(|event| event.hash())?;
        let event = self.events.remove(&hash)?;

        self.peer_list.remove_event(&event);

        Some(event)
    }

    /// Insert event into the `ParsedContents`. Note this does not perform any validations whatsoever,
    /// so this is useful for simulating all kinds of invalid or malicious situations.
    pub fn add_event(&mut self, event: Event<Transaction, PeerId>) {
        unwrap!(self.peer_list.add_event(&event));

        let hash = *event.hash();
        let _ = self.events.insert(hash, event);
    }
}

/// Read a dumped dot file and return with parsed event graph and associated info.
pub(crate) fn parse_dot_file(full_path: &Path) -> io::Result<ParsedContents> {
    let result = unwrap!(read(File::open(full_path)?));
    Ok(convert_into_parsed_contents(result))
}

/// For use by functional/unit tests which provide a dot file for the test setup.  This put the test
/// name as part of the path automatically.
pub(crate) fn parse_test_dot_file(filename: &str) -> ParsedContents {
    parse_dot_file_with_test_name(
        filename,
        &unwrap!(thread::current().name()).replace("::", "_"),
    )
}

/// For use by functional/unit tests which provide a dot file for the test setup.  This reads and
/// parses the dot file as per `parse_dot_file()` above, with test name being part of the path.
pub(crate) fn parse_dot_file_with_test_name(filename: &str, test_name: &str) -> ParsedContents {
    let mut dot_path = PathBuf::from("input_graphs");
    dot_path.push(test_name);
    dot_path.push(filename);
    assert!(
        dot_path.exists(),
        "\nDot file {} doesn't exist.",
        dot_path.display()
    );

    unwrap!(
        parse_dot_file(&dot_path),
        "Failed to parse {}",
        dot_path.display()
    )
}

fn read(mut file: File) -> PomResult<ParsedFile> {
    let mut contents = String::new();
    if file.read_to_string(&mut contents).is_err() {
        return Err(::pom::Error::Custom {
            message: "file not found".to_string(),
            position: 0,
            inner: None,
        });
    }

    let mut input = DataInput::new(contents.as_bytes());
    parse_file().parse(&mut input)
}

fn convert_into_parsed_contents(result: ParsedFile) -> ParsedContents {
    let ParsedFile {
        our_id,
        peer_states,
        mut graph,
        details,
        meta_votes,
    } = result;
    let mut parsed_contents = ParsedContents::new(our_id.clone());
    create_events(&mut graph, &details, &meta_votes, &mut parsed_contents);
    let peer_list = PeerList::new_from_dot_input(our_id, &parsed_contents.events, &peer_states);
    parsed_contents.peer_list = peer_list;
    parsed_contents
}

fn create_events(
    graph: &mut BTreeMap<String, ParsedEvent>,
    details: &BTreeMap<String, EventDetails>,
    meta_votes: &BTreeMap<String, BTreeMap<PeerId, Vec<MetaVote>>>,
    parsed_contents: &mut ParsedContents,
) {
    let mut counts_per_creator = BTreeMap::new();
    let mut event_hashes = BTreeMap::new();
    while !graph.is_empty() {
        let (ev_id, next_parsed_event) = next_topological_event(graph, &event_hashes);
        let next_event_details = unwrap!(details.get(&ev_id));
        let mvs = unwrap!(meta_votes.get(&ev_id));

        let next_event = Event::new_from_dot_input(
            &next_parsed_event.creator,
            &next_event_details.cause,
            next_parsed_event
                .self_parent
                .and_then(|ref id| event_hashes.get(id).cloned()),
            next_parsed_event
                .other_parent
                .and_then(|ref id| event_hashes.get(id).cloned()),
            *counts_per_creator
                .get(&next_parsed_event.creator)
                .unwrap_or(&0),
            next_event_details.last_ancestors.clone(),
            parsed_contents.events.len(),
        );

        if !next_event_details.interesting_content.is_empty() || !mvs.is_empty() {
            let meta_event = {
                let mut builder = MetaEvent::build(MetaElectionHandle::CURRENT, &next_event);
                builder.set_interesting_content(next_event_details.interesting_content.clone());
                builder.set_meta_votes(mvs.clone());
                builder.finish()
            };

            let _ = parsed_contents
                .meta_events
                .insert(*next_event.hash(), meta_event);
        }

        *counts_per_creator
            .entry(next_parsed_event.creator.clone())
            .or_insert(0) += 1;
        let _ = event_hashes.insert(ev_id, *next_event.hash());
        let _ = parsed_contents
            .events
            .insert(*next_event.hash(), next_event);
    }
}

fn next_topological_event(
    graph: &mut BTreeMap<String, ParsedEvent>,
    hashes: &BTreeMap<String, Hash>,
) -> (String, ParsedEvent) {
    let next_key = unwrap!(
        graph
            .iter()
            .filter(|&(_, ref event)| event
                .self_parent
                .as_ref()
                .map(|ev_id| hashes.contains_key(ev_id))
                .unwrap_or(true)
                && event
                    .other_parent
                    .as_ref()
                    .map(|ev_id| hashes.contains_key(ev_id))
                    .unwrap_or(true)).map(|(key, _)| key)
            .next()
    ).clone();
    let ev = unwrap!(graph.remove(&next_key));
    (next_key, ev)
}

#[cfg(all(test, feature = "dump-graphs"))]
mod tests {
    use super::*;
    use dev_utils::{Environment, RngChoice, Schedule, ScheduleOptions};
    use dump_graph::DIR;
    use maidsafe_utilities::serialisation::deserialise;
    use meta_voting::MetaVote;
    use mock::{PeerId, Transaction};
    use std::fs;

    type SerialisedGraph = (
        BTreeMap<Hash, Event<Transaction, PeerId>>,
        BTreeMap<Hash, BTreeMap<PeerId, Vec<MetaVote>>>,
    );

    // Alter the seed here to reproduce failures
    static SEED: RngChoice = RngChoice::SeededRandom;

    #[test]
    fn dot_parser() {
        let mut env = Environment::new(SEED);
        let schedule = Schedule::new(
            &mut env,
            &ScheduleOptions {
                genesis_size: 4,
                opaque_to_add: 5,
                gossip_prob: 0.8,
                ..Default::default()
            },
        );

        let result = env.network.execute_schedule(schedule);
        assert!(result.is_ok(), "{:?}", result);

        let mut num_of_files = 0u8;
        let entries = DIR.with(|dir| unwrap!(fs::read_dir(dir)));
        for entry in entries {
            let entry = unwrap!(entry);

            if !unwrap!(entry.file_name().to_str()).contains(".core") {
                continue;
            }
            num_of_files += 1;
            let mut core_file = unwrap!(File::open(entry.path()));
            let mut core_info = Vec::new();
            assert_ne!(unwrap!(core_file.read_to_end(&mut core_info)), 0);

            let (mut gossip_graph, meta_votes): SerialisedGraph = unwrap!(deserialise(&core_info));

            let mut dot_file_path = entry.path();
            assert!(dot_file_path.set_extension("dot"));
            let parsed_result = unwrap!(parse_dot_file(&dot_file_path));

            assert_eq!(gossip_graph, parsed_result.events);

            // The dumped dot file doesn't contain all the meta_votes
            // NOTE: We only serialise meta-votes in the core file, not complete meta-events.
            // This is why we compare the number of meta-votes (from the core) to the number of
            // meta-events (in the parsed result) here. There is, however, one-to-one mapping
            // between meta-events and sets of meta-votes, so this is correct.
            assert!(meta_votes.len() >= parsed_result.meta_events.len());
            for (hash, meta_event) in &parsed_result.meta_events {
                let ori_meta_vote = unwrap!(meta_votes.get(hash));
                assert_eq!(*ori_meta_vote, meta_event.meta_votes);
            }
        }
        assert_ne!(num_of_files, 0u8);
    }
}
