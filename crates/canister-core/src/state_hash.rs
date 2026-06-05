use crate::state::State;
use crate::types::{CreateAssetArguments, SetAssetContentArguments};
#[cfg(test)]
use itertools::Itertools;
use serde_bytes::ByteBuf;
use sha2::{Digest, Sha256};

const TAG_NONE: [u8; 1] = [2];
const TAG_SOME: [u8; 1] = [3];

const TAG_CREATE_ASSET: [u8; 1] = [4];
const TAG_SET_ASSET_CONTENT: [u8; 1] = [5];

pub enum StateHashComputation {
    InProgress {
        sorted_keys: Vec<String>,
        current_key_index: usize,
        state: VirtualState,
        hasher: Sha256,
    },
    Computed(ByteBuf),
}

#[derive(Clone, Debug)]
pub enum VirtualState {
    CreateAsset,
    SetAssetContent {
        sorted_encoding_names: Vec<String>,
        encoding_index: usize,
    },
    HashChunks {
        sorted_encoding_names: Vec<String>,
        encoding_index: usize,
        chunk_index: usize,
    },
}

impl StateHashComputation {
    pub fn new(state: &State) -> Self {
        let mut sorted_keys: Vec<_> = state.assets.keys().cloned().collect();
        sorted_keys.sort();
        Self::InProgress {
            sorted_keys,
            current_key_index: 0,
            state: VirtualState::CreateAsset,
            hasher: Sha256::new(),
        }
    }

    pub fn advance(self, state: &State) -> Self {
        match self {
            Self::Computed(_) => self,
            Self::InProgress {
                sorted_keys,
                current_key_index,
                state: virtual_state,
                hasher,
            } => next_step(state, sorted_keys, current_key_index, virtual_state, hasher),
        }
    }
}

fn next_step(
    state: &State,
    sorted_keys: Vec<String>,
    current_key_index: usize,
    virtual_state: VirtualState,
    mut hasher: Sha256,
) -> StateHashComputation {
    if current_key_index >= sorted_keys.len() {
        let sha256: [u8; 32] = hasher.finalize().into();
        return StateHashComputation::Computed(ByteBuf::from(sha256));
    }

    let key = &sorted_keys[current_key_index];
    let asset = state.assets.get(key).expect("asset must exist");

    match virtual_state {
        VirtualState::CreateAsset => {
            let args = CreateAssetArguments {
                key: key.clone(),
                content_type: asset.content_type.clone(),
                max_age: asset.max_age,
                headers: asset.headers.clone(),
            };
            hash_create_asset(&mut hasher, &args);
            let mut sorted_encoding_names: Vec<String> = asset.encodings.keys().cloned().collect();
            sorted_encoding_names.sort();

            StateHashComputation::InProgress {
                sorted_keys,
                current_key_index,
                state: VirtualState::SetAssetContent {
                    sorted_encoding_names,
                    encoding_index: 0,
                },
                hasher,
            }
        }
        VirtualState::SetAssetContent {
            sorted_encoding_names,
            encoding_index,
        } => {
            if encoding_index >= sorted_encoding_names.len() {
                return StateHashComputation::InProgress {
                    sorted_keys,
                    current_key_index: current_key_index + 1,
                    state: VirtualState::CreateAsset,
                    hasher,
                };
            }

            let enc_name = &sorted_encoding_names[encoding_index];
            let enc = asset.encodings.get(enc_name).expect("encoding must exist");

            let args = SetAssetContentArguments {
                key: key.clone(),
                content_encoding: enc_name.clone(),
                chunk_ids: vec![],
                last_chunk: None,
                sha256: Some(ByteBuf::from(enc.sha256)),
            };
            hash_set_asset_content(&mut hasher, &args);

            StateHashComputation::InProgress {
                sorted_keys,
                current_key_index,
                state: VirtualState::HashChunks {
                    sorted_encoding_names,
                    encoding_index,
                    chunk_index: 0,
                },
                hasher,
            }
        }
        VirtualState::HashChunks {
            sorted_encoding_names,
            encoding_index,
            chunk_index,
        } => {
            let enc_name = &sorted_encoding_names[encoding_index];
            let enc = asset.encodings.get(enc_name).expect("encoding must exist");

            if chunk_index < enc.content_chunks.len() {
                hasher.update(&enc.content_chunks[chunk_index]);

                StateHashComputation::InProgress {
                    sorted_keys,
                    current_key_index,
                    state: VirtualState::HashChunks {
                        sorted_encoding_names,
                        encoding_index,
                        chunk_index: chunk_index + 1,
                    },
                    hasher,
                }
            } else {
                StateHashComputation::InProgress {
                    sorted_keys,
                    current_key_index,
                    state: VirtualState::SetAssetContent {
                        sorted_encoding_names,
                        encoding_index: encoding_index + 1,
                    },
                    hasher,
                }
            }
        }
    }
}

fn hash_create_asset(hasher: &mut Sha256, args: &CreateAssetArguments) {
    hasher.update(TAG_CREATE_ASSET);
    hasher.update(&args.key);
    hasher.update(&args.content_type);
    if let Some(max_age) = args.max_age {
        hasher.update(TAG_SOME);
        hasher.update(max_age.to_be_bytes());
    } else {
        hasher.update(TAG_NONE);
    }
    hash_headers(hasher, args.headers.as_ref());
}

fn hash_set_asset_content(hasher: &mut Sha256, args: &SetAssetContentArguments) {
    hasher.update(TAG_SET_ASSET_CONTENT);
    hasher.update(&args.key);
    hasher.update(&args.content_encoding);
    hash_opt_bytebuf(hasher, args.sha256.as_ref());
}

fn hash_opt_bytebuf(hasher: &mut Sha256, buf: Option<&ByteBuf>) {
    if let Some(buf) = buf {
        hasher.update(TAG_SOME);
        hasher.update(buf);
    } else {
        hasher.update(TAG_NONE);
    }
}

fn hash_headers(hasher: &mut Sha256, headers: Option<&Vec<(String, String)>>) {
    if let Some(headers) = headers {
        hasher.update(TAG_SOME);
        // Stable-sort by lowercased name only so multi-valued headers
        // (e.g. Set-Cookie) preserve their declaration order — required
        // because RFC 6265 §5.3 makes the last same-name cookie win.
        let mut indexed: Vec<(usize, &(String, String))> = headers.iter().enumerate().collect();
        indexed.sort_by(|(ai, (ak, _)), (bi, (bk, _))| {
            let an = ak.to_ascii_lowercase();
            let bn = bk.to_ascii_lowercase();
            an.cmp(&bn).then(ai.cmp(bi))
        });
        for (_, (k, v)) in indexed {
            hasher.update(k);
            hasher.update(v);
        }
    } else {
        hasher.update(TAG_NONE);
    }
}

#[test]
fn tag_value_uniqueness() {
    let tags = include_str!("state_hash.rs")
        .lines()
        .filter(|l| l.starts_with("const TAG_"))
        .map(|line| {
            line.split(": [u8; 1] = [")
                .nth(1)
                .unwrap()
                .trim_end_matches("];")
                .parse::<u8>()
                .unwrap()
        });
    assert_eq!(
        tags.clone().count(),
        tags.unique().count(),
        "tag values must be unique"
    );
}
