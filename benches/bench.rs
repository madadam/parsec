// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/maidsafe/QA/master/Images/maidsafe_logo.png",
    html_favicon_url = "https://maidsafe.net/img/favicon.ico",
    html_root_url = "https://docs.rs/parsec"
)]
#![forbid(
    exceeding_bitshifts,
    mutable_transmutes,
    no_mangle_const_items,
    unknown_crate_types,
    warnings
)]
#![deny(
    bad_style,
    deprecated,
    improper_ctypes,
    non_shorthand_field_patterns,
    overflowing_literals,
    plugin_as_library,
    private_no_mangle_fns,
    private_no_mangle_statics,
    stable_features,
    unconditional_recursion,
    unknown_lints,
    unsafe_code,
    unused_allocation,
    unused_attributes,
    unused_comparisons,
    unused_features,
    unused_parens,
    while_true
)]
#![warn(
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results
)]
#![allow(
    box_pointers,
    missing_copy_implementations,
    missing_debug_implementations,
    variant_size_differences
)]

#[macro_use]
#[cfg(feature = "testing")]
extern crate criterion;
#[cfg(feature = "testing")]
extern crate parsec;

#[cfg(feature = "testing")]
use criterion::Criterion;

#[cfg(feature = "testing")]
use parsec::dev_utils::{Environment, RngChoice, Schedule};

#[cfg(feature = "testing")]
fn bench(c: &mut Criterion) {
    let _ = c.bench_function("minimal", |b| {
        b.iter_with_setup(
            || {
                let mut env = Environment::new(RngChoice::SeededRandom);
                let schedule = Schedule::build(&mut env).finish();

                (env, schedule)
            },
            |(mut env, schedule)| {
                let _ = env.network.execute_schedule(schedule);
            },
        )
    });
}

#[cfg(feature = "testing")]
criterion_group!(benches, bench);

#[cfg(feature = "testing")]
criterion_main!(benches);

#[cfg(not(feature = "testing"))]
fn main() {
    println!("For benchmark tests, run with '--features=testing'.");
}
