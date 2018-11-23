// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use gossip::{CauseInput, Event, EventIndex, Graph, IndexedEventRef};
use hash::Hash;
use hash::HASH_LEN;
use meta_voting::{
    BoolSet, ConsensusInfo, MetaElection, MetaElectionHandle, MetaElections, MetaEvent, MetaVote,
    Step,
};
use mock::{PeerId, Transaction};
use observation::{Observation, ObservationHash};
use peer_list::{PeerList, PeerState};
use pom::char_class::{alphanum, digit, hex_digit, multispace, space};
use pom::parser::*;
use pom::Result as PomResult;
use pom::{DataInput, Parser};
use round_hash::RoundHash;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use std::str::FromStr;

pub const HEX_DIGITS_PER_BYTE: usize = 2;

type ObservationMap = Vec<(ObservationHash, Observation<Transaction, PeerId>)>;

fn newline() -> Parser<u8, ()> {
    (seq(b"\n") | seq(b"\r\n")).discard()
}

fn next_line() -> Parser<u8, ()> {
    none_of(b"\r\n").repeat(0..) * newline()
}

// Skip spaces or tabs.
fn spaces() -> Parser<u8, ()> {
    is_a(space).repeat(0..).discard()
}

// Skip any whitespace including newlines.
fn whitespace() -> Parser<u8, ()> {
    is_a(multispace).repeat(0..).discard()
}

fn comment_prefix() -> Parser<u8, ()> {
    seq(b"///") * spaces()
}

#[derive(Debug)]
struct ParsedFile {
    our_id: PeerId,
    peer_list: ParsedPeerList,
    graph: ParsedGraph,
    meta_elections: ParsedMetaElections,
}

fn parse_file() -> Parser<u8, ParsedFile> {
    (parse_our_id() + parse_peer_list() + parse_graph() + parse_meta_elections() - parse_end()).map(
        |(((our_id, peer_list), graph), meta_elections)| ParsedFile {
            our_id,
            peer_list,
            graph,
            meta_elections,
        },
    )
}

fn parse_peer_id() -> Parser<u8, PeerId> {
    is_a(alphanum)
        .repeat(1..)
        .collect()
        .convert(String::from_utf8)
        .map(|s| PeerId::new(&s))
}

fn parse_our_id() -> Parser<u8, PeerId> {
    comment_prefix() * seq(b"our_id: ") * parse_peer_id() - next_line()
}

#[derive(Debug)]
struct ParsedPeerList(BTreeMap<PeerId, ParsedPeer>);

#[derive(Debug)]
struct ParsedPeer {
    state: PeerState,
    membership_list: BTreeSet<PeerId>,
}

fn parse_peer_list() -> Parser<u8, ParsedPeerList> {
    let list_defs =
        comment_prefix() * seq(b"peer_list: {") * next_line() * parse_peer().repeat(0..)
            - comment_prefix()
            - sym(b'}') * next_line();
    list_defs.map(|defs| ParsedPeerList(defs.into_iter().collect()))
}

fn parse_peer() -> Parser<u8, (PeerId, ParsedPeer)> {
    let list_def = comment_prefix() * parse_peer_id() - seq(b"; ") + parse_peer_state()
        - seq(b"; peers: ")
        + parse_peers()
        - next_line();
    list_def.map(|((id, state), membership_list)| {
        (
            id,
            ParsedPeer {
                state,
                membership_list,
            },
        )
    })
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

#[derive(Debug)]
struct ParsedGraph {
    graph: BTreeMap<String, ParsedEvent>,
    event_details: BTreeMap<String, EventDetails>,
}

#[derive(Debug)]
struct ParsedEvent {
    creator: PeerId,
    self_parent: Option<String>,
    other_parent: Option<String>,
}

const SKIP_DIGRAPH_INITIAL_PROPS: usize = 4;
const SKIP_STYLE_INVIS: usize = 3;

fn parse_graph() -> Parser<u8, ParsedGraph> {
    let subgraphs = seq(b"digraph GossipGraph")
        * next_line().repeat(SKIP_DIGRAPH_INITIAL_PROPS)
        * parse_subgraph().repeat(1..)
        - (none_of(b"}").repeat(0..) * one_of(b"}"))
        - next_line().repeat(SKIP_STYLE_INVIS)
        + parse_event_details()
        - seq(b"}")
        - next_line().repeat(2);
    subgraphs.map(|(graphs, details)| {
        let mut graph = BTreeMap::new();
        for subgraph in graphs {
            for event in subgraph.events {
                let self_parent = subgraph.self_parents.get(&event).cloned();
                let other_parent = subgraph.other_parents.get(&event).cloned();
                let _ = graph.insert(
                    event.clone(),
                    ParsedEvent {
                        creator: subgraph.creator.clone(),
                        self_parent,
                        other_parent,
                    },
                );
            }
        }
        ParsedGraph {
            graph,
            event_details: details,
        }
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
    self_parents: BTreeMap<String, String>,
    other_parents: BTreeMap<String, String>,
}

const SKIP_AFTER_SUBGRAPH: usize = 3;

fn parse_subgraph() -> Parser<u8, ParsedSubgraph> {
    let id = whitespace()
        * seq(b"style=invis")
        * whitespace()
        * seq(b"subgraph cluster_")
        * parse_peer_id();

    let self_parents = whitespace()
        * sym(b'{')
        * next_line().repeat(SKIP_AFTER_SUBGRAPH)
        * parse_edge().repeat(0..)
        - whitespace()
        - sym(b'}');
    let other_parents = whitespace() * parse_edge().repeat(0..);

    // `self_parents` will contain the creator's line - we are only interested in the set of events at the
    // end of edges
    (id + self_parents + other_parents).map(|((id, self_parents), other_parents)| {
        let events = self_parents.iter().map(|edge| edge.end.clone()).collect();
        ParsedSubgraph {
            creator: id,
            events,
            self_parents: self_parents
                .into_iter()
                .skip(1)    // skip the edge creator_id -> initial_event
                .map(|edge| (edge.end, edge.start))
                .collect(),
            other_parents: other_parents
                .into_iter()
                .map(|edge| (edge.end, edge.start))
                .collect(),
        }
    })
}

fn parse_edge() -> Parser<u8, ParsedEdge> {
    (spaces() * sym(b'"') * parse_event_id() - seq(b"\" -> \"") + parse_event_id() - next_line())
        .map(|(id1, id2)| ParsedEdge {
            start: id1,
            end: id2,
        })
}

fn parse_event_id() -> Parser<u8, String> {
    is_a(|c| alphanum(c) || c == b'_')
        .repeat(1..)
        .convert(String::from_utf8)
}

fn parse_event_details() -> Parser<u8, BTreeMap<String, EventDetails>> {
    seq(b"/// ===== details of events") * next_line() * parse_single_event_detail()
        .repeat(1..)
        .map(|details| details.into_iter().collect())
}

#[derive(Debug)]
struct EventDetails {
    cause: CauseInput,
    last_ancestors: BTreeMap<PeerId, usize>,
}

fn skip_brackets() -> Parser<u8, ()> {
    sym(b'[') * (none_of(b"[]").discard() | call(skip_brackets)).repeat(0..) * sym(b']').discard()
}

fn parse_single_event_detail() -> Parser<u8, (String, EventDetails)> {
    (spaces() * sym(b'"') * parse_event_id() - seq(b"\" ") - skip_brackets() - next_line()
        + parse_cause()
        + parse_last_ancestors()
        - next_line()).map(|((id, cause), last_ancestors)| {
        (
            id,
            EventDetails {
                cause,
                last_ancestors,
            },
        )
    })
}

fn parse_cause() -> Parser<u8, CauseInput> {
    let prefix = comment_prefix() * seq(b"cause: ");
    let initial = seq(b"Initial").map(|_| CauseInput::Initial);
    let request = seq(b"Request").map(|_| CauseInput::Request);
    let response = seq(b"Response").map(|_| CauseInput::Response);
    let observation =
        (seq(b"Observation(") * parse_observation() - sym(b')')).map(CauseInput::Observation);

    prefix * (initial | request | response | observation) - newline()
}

fn parse_last_ancestors() -> Parser<u8, BTreeMap<PeerId, usize>> {
    (comment_prefix() * seq(b"last_ancestors: {") * list(
        parse_peer_id() - seq(b": ") + is_a(digit)
            .repeat(1..)
            .convert(String::from_utf8)
            .convert(|s| usize::from_str(&s)),
        seq(b", "),
    ) - next_line()).map(|v| v.into_iter().collect())
}

#[derive(Debug)]
struct ParsedMetaElections {
    consensus_history: Vec<ConsensusInfo>,
    meta_elections: BTreeMap<MetaElectionHandle, ParsedMetaElection>,
}

fn parse_meta_elections() -> Parser<u8, ParsedMetaElections> {
    (seq(b"/// ===== meta-elections =====")
     * next_line()
     * parse_consensus_history()
     + parse_meta_election().repeat(0..))
        .map(|(consensus_history, meta_elections)| ParsedMetaElections {
            consensus_history,
            meta_elections: meta_elections.into_iter().collect()
        })
}

fn parse_consensus_history() -> Parser<u8, Vec<ConsensusInfo>> {
    let hash_line = comment_prefix() * (parse_hash()).map(ObservationHash) - next_line();
    let hash_line = hash_line.map(|hash| ConsensusInfo {
        hash,
        carriers: BTreeSet::new(),
    });
    comment_prefix() * seq(b"consensus_history:") * next_line() * hash_line.repeat(0..)
}

fn parse_hash() -> Parser<u8, Hash> {
    is_a(hex_digit)
        .repeat(HEX_DIGITS_PER_BYTE)
        .convert(String::from_utf8)
        .convert(|s| u8::from_str_radix(&s, 16))
        .repeat(HASH_LEN)
        .map(|v| {
            let mut bytes = [0; HASH_LEN];
            for (i, byte) in v.into_iter().enumerate() {
                bytes[i] = byte;
            }
            Hash::from_bytes(bytes)
        })
}

#[derive(Debug)]
struct ParsedMetaElection {
    consensus_len: usize,
    round_hashes: BTreeMap<PeerId, Vec<RoundHash>>,
    interesting_events: BTreeMap<PeerId, Vec<String>>,
    all_voters: BTreeSet<PeerId>,
    undecided_voters: BTreeSet<PeerId>,
    payload: Option<Observation<Transaction, PeerId>>,
    start_index: usize,
    observation_map: BTreeMap<ObservationHash, Observation<Transaction, PeerId>>,
    meta_events: BTreeMap<String, MetaEvent<PeerId>>,
}

fn parse_meta_election() -> Parser<u8, (MetaElectionHandle, ParsedMetaElection)> {
    next_line() * parse_meta_election_handle()
        + (parse_consensus_len()
            + parse_round_hashes()
            + parse_interesting_events()
            + parse_all_voters()
            + parse_undecided_voters()
            + parse_payload().opt()
            + parse_start_index().opt()
            + parse_meta_events()).map(
            |(
                (
                    (
                        (
                            (((consensus_len, round_hashes), interesting_events), all_voters),
                            undecided_voters,
                        ),
                        payload,
                    ),
                    start_index,
                ),
                observation_map_and_meta_events,
            )| {
                let mut observation_map = BTreeMap::new();
                let mut meta_events = BTreeMap::new();
                for (id, (obs, m_ev)) in observation_map_and_meta_events {
                    observation_map.extend(obs);
                    let _ = meta_events.insert(id, m_ev);
                }

                ParsedMetaElection {
                    consensus_len,
                    round_hashes,
                    interesting_events,
                    all_voters,
                    undecided_voters,
                    payload,
                    start_index: start_index.unwrap_or(0),
                    observation_map,
                    meta_events,
                }
            },
        )
}

fn parse_meta_election_handle() -> Parser<u8, MetaElectionHandle> {
    comment_prefix()
        * seq(b"MetaElectionHandle(")
        * (seq(b"CURRENT").map(|_| MetaElectionHandle::CURRENT) | is_a(digit)
            .repeat(1..)
            .convert(String::from_utf8)
            .convert(|s| usize::from_str(&s))
            .map(MetaElectionHandle))
        - sym(b')')
        - next_line()
}

fn parse_consensus_len() -> Parser<u8, usize> {
    comment_prefix() * seq(b"consensus_len: ") * parse_usize() - next_line()
}

fn parse_round_hashes() -> Parser<u8, BTreeMap<PeerId, Vec<RoundHash>>> {
    (comment_prefix()
        * seq(b"round_hashes: {")
        * next_line()
        * parse_round_hashes_for_peer().repeat(0..)
        - comment_prefix()
        - seq(b"}")
        - next_line()).map(|v| v.into_iter().collect())
}

fn parse_round_hashes_for_peer() -> Parser<u8, (PeerId, Vec<RoundHash>)> {
    (comment_prefix() * parse_peer_id() - seq(b" -> [") - next_line()
        + parse_single_round_hash().repeat(0..)
        - comment_prefix()
        - sym(b']')
        - next_line()).map(|(id, hashes)| {
        let round_hashes = hashes
            .into_iter()
            .map(|hash| RoundHash::new_with_round(&id, ObservationHash(hash.1), hash.0))
            .collect();
        (id, round_hashes)
    })
}

fn parse_single_round_hash() -> Parser<u8, (usize, Hash)> {
    comment_prefix() * seq(b"RoundHash { round: ") * parse_usize() - seq(b", latest_block_hash: ")
        + parse_hash()
        - next_line()
}

fn parse_usize() -> Parser<u8, usize> {
    is_a(digit)
        .repeat(1..)
        .convert(String::from_utf8)
        .convert(|s| usize::from_str(&s))
}

fn parse_interesting_events() -> Parser<u8, BTreeMap<PeerId, Vec<String>>> {
    (comment_prefix()
        * seq(b"interesting_events: {")
        * next_line()
        * parse_interesting_events_for_peer().repeat(0..)
        - comment_prefix()
        - sym(b'}')
        - next_line()).map(|v| v.into_iter().collect())
}

fn parse_interesting_events_for_peer() -> Parser<u8, (PeerId, Vec<String>)> {
    comment_prefix() * parse_peer_id() - seq(b" -> [")
        + list(sym(b'"') * parse_event_id() - sym(b'"'), seq(b", "))
        - seq(b"]")
        - next_line()
}

fn parse_all_voters() -> Parser<u8, BTreeSet<PeerId>> {
    comment_prefix() * seq(b"all_voters: ") * parse_peers() - next_line()
}

fn parse_undecided_voters() -> Parser<u8, BTreeSet<PeerId>> {
    comment_prefix() * seq(b"undecided_voters: ") * parse_peers() - next_line()
}

fn parse_payload() -> Parser<u8, Observation<Transaction, PeerId>> {
    comment_prefix() * seq(b"payload: ") * parse_observation() - next_line()
}

fn parse_start_index() -> Parser<u8, usize> {
    comment_prefix() * seq(b"start_index: ") * parse_usize() - next_line()
}

fn parse_observation() -> Parser<u8, Observation<Transaction, PeerId>> {
    parse_genesis() | parse_add() | parse_remove() | parse_opaque()
}

fn parse_genesis() -> Parser<u8, Observation<Transaction, PeerId>> {
    (seq(b"Genesis(") * parse_peers() - seq(b")")).map(Observation::Genesis)
}

fn parse_add() -> Parser<u8, Observation<Transaction, PeerId>> {
    seq(b"Add") * parse_add_or_remove().map(|(peer_id, related_info)| Observation::Add {
        peer_id,
        related_info,
    })
}

fn parse_remove() -> Parser<u8, Observation<Transaction, PeerId>> {
    seq(b"Remove") * parse_add_or_remove().map(|(peer_id, related_info)| Observation::Remove {
        peer_id,
        related_info,
    })
}

fn parse_add_or_remove() -> Parser<u8, (PeerId, Vec<u8>)> {
    parse_add_or_remove_with_related_info() | parse_add_or_remove_without_related_info()
}

fn parse_add_or_remove_with_related_info() -> Parser<u8, (PeerId, Vec<u8>)> {
    let peer_id = seq(b"peer_id:") * spaces() * parse_peer_id();
    let related_info =
        seq(b"related_info:") * spaces() * sym(b'[') * none_of(b"]").repeat(0..) - sym(b']');

    spaces() * sym(b'{') * spaces() * peer_id - spaces() - sym(b',') - spaces() + related_info
        - spaces()
        - sym(b'}')
}

fn parse_add_or_remove_without_related_info() -> Parser<u8, (PeerId, Vec<u8>)> {
    (spaces() * sym(b'(') * spaces() * parse_peer_id() - spaces() - sym(b')'))
        .map(|peer_id| (peer_id, vec![]))
}

fn parse_opaque() -> Parser<u8, Observation<Transaction, PeerId>> {
    (seq(b"OpaquePayload(") * parse_transaction() - seq(b")"))
        .map(|s| Transaction::new(&s))
        .map(Observation::OpaquePayload)
}

fn parse_transaction() -> Parser<u8, String> {
    is_a(alphanum).repeat(1..).convert(String::from_utf8)
}

fn parse_meta_events() -> Parser<u8, BTreeMap<String, (ObservationMap, MetaEvent<PeerId>)>> {
    (comment_prefix()
        * seq(b"meta_events: {")
        * next_line()
        * parse_single_meta_event().repeat(1..)
        - comment_prefix()
        - sym(b'}')
        - next_line()).map(|v| v.into_iter().collect())
}

fn parse_single_meta_event() -> Parser<u8, (String, (ObservationMap, MetaEvent<PeerId>))> {
    comment_prefix() * parse_event_id() - seq(b" -> {") - next_line() + parse_meta_event_content()
        - comment_prefix()
        - sym(b'}')
        - next_line()
}

fn parse_meta_event_content() -> Parser<u8, (ObservationMap, MetaEvent<PeerId>)> {
    (parse_observees() + parse_interesting_content() + parse_meta_votes().opt()).map(
        |((observees, observation_map), meta_votes)| {
            let interesting_content = observation_map.iter().map(|(hash, _)| *hash).collect();
            (
                observation_map,
                MetaEvent {
                    observees,
                    interesting_content,
                    meta_votes: meta_votes.unwrap_or_else(BTreeMap::new),
                },
            )
        },
    )
}

fn parse_observees() -> Parser<u8, BTreeSet<PeerId>> {
    comment_prefix() * seq(b"observees: ") * parse_peers() - next_line()
}

fn parse_interesting_content() -> Parser<u8, ObservationMap> {
    (comment_prefix() * seq(b"interesting_content: [") * list(parse_observation(), seq(b", "))
        - next_line()).map(|observations| {
        observations
            .into_iter()
            .map(|payload| (ObservationHash::from(&payload), payload))
            .collect()
    })
}

fn parse_meta_votes() -> Parser<u8, BTreeMap<PeerId, Vec<MetaVote>>> {
    (comment_prefix()
        * seq(b"meta_votes: {")
        * next_line()
        * next_line()
        * parse_peer_meta_votes().repeat(0..)
        - comment_prefix()
        - sym(b'}')
        - next_line()).map(|v| v.into_iter().collect())
}

fn parse_peer_meta_votes() -> Parser<u8, (PeerId, Vec<MetaVote>)> {
    let peer_line = comment_prefix() * is_a(alphanum).map(char::from) - seq(b": ")
        + parse_meta_vote()
        - next_line();
    let next_line = comment_prefix() * parse_meta_vote() - next_line();
    (peer_line + next_line.repeat(0..)).map(|((peer_initial, first_mv), other_mvs)| {
        let mut mvs = vec![first_mv];
        mvs.extend(other_mvs);
        (PeerId::from_initial(peer_initial), mvs)
    })
}

fn parse_meta_vote() -> Parser<u8, MetaVote> {
    (parse_usize() - sym(b'/') + parse_usize() - spaces() + parse_bool_set() - spaces()
        + parse_bool_set()
        - spaces()
        + parse_opt_bool()
        - spaces()
        + parse_opt_bool()).map(|(((((round, step), est), bin), aux), dec)| MetaVote {
        round,
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

fn parse_bool_set() -> Parser<u8, BoolSet> {
    sym(b'-').map(|_| BoolSet::Empty)
        | sym(b'f').map(|_| BoolSet::Single(false))
        | sym(b't').map(|_| BoolSet::Single(true))
        | sym(b'b').map(|_| BoolSet::Both)
}

fn parse_opt_bool() -> Parser<u8, Option<bool>> {
    sym(b'-').map(|_| None) | sym(b'f').map(|_| Some(false)) | sym(b't').map(|_| Some(true))
}

fn parse_end() -> Parser<u8, ()> {
    one_of(b" \r\n").repeat(0..) * end()
}

/// The event graph and associated info that were parsed from the dumped dot file.
pub(crate) struct ParsedContents {
    pub our_id: PeerId,
    pub graph: Graph<Transaction, PeerId>,
    pub meta_elections: MetaElections<PeerId>,
    pub peer_list: PeerList<PeerId>,
    pub observation_map: BTreeMap<ObservationHash, Observation<Transaction, PeerId>>,
}

impl ParsedContents {
    /// Create empty `ParsedContents`.
    pub fn new(our_id: PeerId) -> Self {
        let peer_list = PeerList::new(our_id.clone());
        let meta_elections = MetaElections::new(BTreeSet::new());

        ParsedContents {
            our_id,
            graph: Graph::new(),
            meta_elections,
            peer_list,
            observation_map: BTreeMap::new(),
        }
    }
}

#[cfg(all(test, feature = "mock"))]
impl ParsedContents {
    /// Remove and return the last (newest) event from the `ParsedContents`, if any.
    pub fn remove_last_event(&mut self) -> Option<Event<Transaction, PeerId>> {
        let (index_0, event) = self.graph.remove_last()?;
        let index_1 = self.peer_list.remove_last_event(event.creator());
        assert_eq!(Some(index_0), index_1);

        Some(event)
    }

    #[cfg(feature = "malice-detection")]
    /// Insert event into the `ParsedContents`. Note this does not perform any validations whatsoever,
    /// so this is useful for simulating all kinds of invalid or malicious situations.
    pub fn add_event(&mut self, event: Event<Transaction, PeerId>) {
        let indexed_event = self.graph.insert(event);
        self.peer_list.add_event(indexed_event);
    }
}

/// Read a dumped dot file and return with parsed event graph and associated info.
pub(crate) fn parse_dot_file<P: AsRef<Path>>(full_path: P) -> io::Result<ParsedContents> {
    let result = unwrap!(read(File::open(full_path)?));
    Ok(convert_into_parsed_contents(result))
}

/// For use by functional/unit tests which provide a dot file for the test setup.  This put the test
/// name as part of the path automatically.
#[cfg(test)]
pub(crate) fn parse_test_dot_file(filename: &str) -> ParsedContents {
    use std::thread;

    parse_dot_file_with_test_name(
        filename,
        &unwrap!(thread::current().name()).replace("::", "_"),
    )
}

/// For use by functional/unit tests which provide a dot file for the test setup.  This reads and
/// parses the dot file as per `parse_dot_file()` above, with test name being part of the path.
#[cfg(test)]
pub(crate) fn parse_dot_file_with_test_name(filename: &str, test_name: &str) -> ParsedContents {
    use std::path::PathBuf;

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
        peer_list,
        mut graph,
        meta_elections,
    } = result;

    let mut parsed_contents = ParsedContents::new(our_id.clone());
    let mut event_hashes =
        create_events(&mut graph.graph, graph.event_details, &mut parsed_contents);

    let peer_data = peer_list
        .0
        .into_iter()
        .map(|(id, data)| (id, (data.state, data.membership_list)))
        .collect();
    let peer_list = PeerList::new_from_dot_input(our_id, &parsed_contents.graph, peer_data);

    parsed_contents.peer_list = peer_list;
    parsed_contents.observation_map = meta_elections
        .meta_elections
        .values()
        .flat_map(|meta_election| {
            meta_election
                .observation_map
                .iter()
                .map(|(hash, obs)| (*hash, obs.clone()))
        }).collect();
    parsed_contents.meta_elections = convert_to_meta_elections(meta_elections, &mut event_hashes);
    parsed_contents
}

fn convert_to_meta_elections(
    meta_elections: ParsedMetaElections,
    event_indices: &mut BTreeMap<String, EventIndex>,
) -> MetaElections<PeerId> {
    let meta_elections_map = meta_elections
        .meta_elections
        .into_iter()
        .map(|(handle, election)| {
            (
                handle,
                convert_to_meta_election(handle, election, event_indices),
            )
        }).collect();
    MetaElections::from_map_and_history(meta_elections_map, meta_elections.consensus_history)
}

fn convert_to_meta_election(
    handle: MetaElectionHandle,
    meta_election: ParsedMetaElection,
    event_indices: &mut BTreeMap<String, EventIndex>,
) -> MetaElection<PeerId> {
    MetaElection {
        meta_events: meta_election
            .meta_events
            .into_iter()
            .map(|(ev_id, mev)| {
                (
                    *event_indices
                        .entry(ev_id.clone())
                        .or_insert_with(|| EventIndex::PHONY),
                    mev,
                )
            }).collect(),
        round_hashes: meta_election.round_hashes,
        all_voters: meta_election.all_voters,
        undecided_voters: meta_election.undecided_voters,
        interesting_events: meta_election
            .interesting_events
            .into_iter()
            .map(|(peer_id, events)| {
                (
                    peer_id,
                    events
                        .into_iter()
                        .map(|ev_id| {
                            *unwrap!(
                                event_indices.get(&ev_id),
                                "Missing {:?} from meta_events section of meta election {:?}.  \
                                This meta-event must be defined here as it's an Interesting Event.",
                                ev_id,
                                handle
                            )
                        }).collect(),
                )
            }).collect(),
        consensus_len: meta_election.consensus_len,
        start_index: meta_election.start_index,
        payload_hash: meta_election.payload.as_ref().map(ObservationHash::from),
    }
}

fn create_events(
    graph: &mut BTreeMap<String, ParsedEvent>,
    mut details: BTreeMap<String, EventDetails>,
    parsed_contents: &mut ParsedContents,
) -> BTreeMap<String, EventIndex> {
    let mut event_indices = BTreeMap::new();

    while !graph.is_empty() {
        let (ev_id, next_parsed_event) = next_topological_event(graph, &event_indices);
        let next_event_details = unwrap!(details.remove(&ev_id));

        let (self_parent, other_parent, index_by_creator) = {
            let self_parent = next_parsed_event
                .self_parent
                .and_then(|ref id| get_event_by_id(&parsed_contents.graph, &event_indices, id));

            let other_parent = next_parsed_event
                .other_parent
                .and_then(|ref id| get_event_by_id(&parsed_contents.graph, &event_indices, id));

            let index_by_creator = self_parent
                .map(|ie| ie.index_by_creator() + 1)
                .unwrap_or(0usize);

            (
                self_parent.map(|e| (e.event_index(), *e.hash())),
                other_parent.map(|e| (e.event_index(), *e.hash())),
                index_by_creator,
            )
        };

        let next_event = Event::new_from_dot_input(
            &next_parsed_event.creator,
            next_event_details.cause,
            self_parent,
            other_parent,
            index_by_creator,
            next_event_details.last_ancestors.clone(),
        );

        let index = parsed_contents.graph.insert(next_event).event_index();
        let _ = event_indices.insert(ev_id, index);
    }

    event_indices
}

fn get_event_by_id<'a>(
    graph: &'a Graph<Transaction, PeerId>,
    indices: &BTreeMap<String, EventIndex>,
    id: &str,
) -> Option<IndexedEventRef<'a, Transaction, PeerId>> {
    indices.get(id).cloned().and_then(|index| graph.get(index))
}

fn next_topological_event(
    graph: &mut BTreeMap<String, ParsedEvent>,
    indices: &BTreeMap<String, EventIndex>,
) -> (String, ParsedEvent) {
    let next_key = unwrap!(
        graph
            .iter()
            .filter(|&(_, ref event)| event
                .self_parent
                .as_ref()
                .map(|ev_id| indices.contains_key(ev_id))
                .unwrap_or(true)
                && event
                    .other_parent
                    .as_ref()
                    .map(|ev_id| indices.contains_key(ev_id))
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
    use gossip::GraphSnapshot;
    use maidsafe_utilities::serialisation::deserialise;
    use meta_voting::MetaElectionsSnapshot;
    use mock::PeerId;
    use std::fs;

    type Snapshot = (GraphSnapshot, MetaElectionsSnapshot<PeerId>);

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

        unwrap!(env.network.execute_schedule(schedule));

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
            let expected_snapshot: Snapshot = unwrap!(deserialise(&core_info));

            let mut dot_file_path = entry.path();
            assert!(dot_file_path.set_extension("dot"));
            let parsed = unwrap!(parse_dot_file(&dot_file_path));
            let actual_snapshot = (
                GraphSnapshot::new(&parsed.graph),
                MetaElectionsSnapshot::new(&parsed.meta_elections, &parsed.graph),
            );

            assert_eq!(actual_snapshot, expected_snapshot);
        }
        assert_ne!(num_of_files, 0u8);
    }
}
