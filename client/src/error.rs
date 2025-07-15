// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

use bitcoin::hashes::hex;
use bitcoin::secp256k1;

/// The error type for errors produced in this library.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("JSON-RPC error: {0}")]
    Rpc(#[from] jsonrpsee::core::ClientError),

    #[error("hex decode error: {0}")]
    Hex(#[from] bitcoin::consensus::encode::FromHexError),

    #[error("hex encode error: {0}")]
    Hex2(#[from] hex::HexToBytesError),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Bitcoin serialization error: {0}")]
    BitcoinSerialization(#[from] bitcoin::consensus::encode::Error),

    #[error("secp256k1 error: {0}")]
    Secp256k1(#[from] secp256k1::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("invalid amount: {0}")]
    InvalidAmount(#[from] bitcoin::amount::ParseAmountError),

    #[error("invalid cookie file")]
    InvalidCookieFile,

    #[error("the JSON result had an unexpected structure")]
    UnexpectedStructure,

    #[error("the daemon returned an error string: {0}")]
    ReturnedError(String),
}
