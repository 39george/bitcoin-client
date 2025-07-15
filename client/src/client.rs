use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::{fmt, result};

use base64::Engine;
use base64::engine::general_purpose;
use bitcoin::address::{NetworkChecked, NetworkUnchecked};
use bitcoin::consensus::encode;
use bitcoin::hashes::hex::FromHex;
use bitcoin::hex::DisplayHex;
use bitcoin::secp256k1::ecdsa::Signature;
use bitcoin::{Address, Amount, Block, OutPoint, PrivateKey, PublicKey, Script, Transaction};
use http::{HeaderMap, HeaderValue, header};
use jsonrpsee::core::client::ClientT;
use jsonrpsee::core::params::ArrayParams;
use serde::{self, Deserialize, Serialize};

use crate::error::*;
use crate::queryable;

const NOPARAMS: &[serde_json::Value] = &[];

/// Crate-specific Result type, shorthand for `std::result::Result` with our
/// crate-specific Error type;
pub type Result<T> = result::Result<T, Error>;

/// Outpoint that serializes and deserializes as a map, instead of a string,
/// for use as RPC arguments
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonOutPoint {
    pub txid: bitcoin::Txid,
    pub vout: u32,
}

impl From<OutPoint> for JsonOutPoint {
    fn from(o: OutPoint) -> JsonOutPoint {
        JsonOutPoint {
            txid: o.txid,
            vout: o.vout,
        }
    }
}

impl From<JsonOutPoint> for OutPoint {
    fn from(val: JsonOutPoint) -> Self {
        OutPoint {
            txid: val.txid,
            vout: val.vout,
        }
    }
}

/// Shorthand for converting a variable into a serde_json::Value.
fn into_json<T>(val: T) -> Result<serde_json::Value>
where
    T: serde::ser::Serialize,
{
    Ok(serde_json::to_value(val)?)
}

/// Shorthand for converting an Option into an Option<serde_json::Value>.
fn opt_into_json<T>(opt: Option<T>) -> Result<serde_json::Value>
where
    T: serde::ser::Serialize,
{
    match opt {
        Some(val) => Ok(into_json(val)?),
        None => Ok(serde_json::Value::Null),
    }
}

/// Shorthand for `serde_json::Value::Null`.
fn null() -> serde_json::Value {
    serde_json::Value::Null
}

/// Shorthand for an empty serde_json::Value array.
fn empty_arr() -> serde_json::Value {
    serde_json::Value::Array(vec![])
}

/// Shorthand for an empty serde_json object.
fn empty_obj() -> serde_json::Value {
    serde_json::Value::Object(Default::default())
}

/// Handle default values in the argument list
///
/// Substitute `Value::Null`s with corresponding values from `defaults` table,
/// except when they are trailing, in which case just skip them altogether
/// in returned list.
///
/// Note, that `defaults` corresponds to the last elements of `args`.
///
/// ```norust
/// arg1 arg2 arg3 arg4
///           def1 def2
/// ```
///
/// Elements of `args` without corresponding `defaults` value, won't
/// be substituted, because they are required.
fn handle_defaults<'a>(
    args: &'a mut [serde_json::Value],
    defaults: &[serde_json::Value],
) -> &'a [serde_json::Value] {
    assert!(args.len() >= defaults.len());

    // Pass over the optional arguments in backwards order, filling in defaults after the first
    // non-null optional argument has been observed.
    let mut first_non_null_optional_idx = None;
    for i in 0..defaults.len() {
        let args_i = args.len() - 1 - i;
        let defaults_i = defaults.len() - 1 - i;
        if args[args_i] == serde_json::Value::Null {
            if first_non_null_optional_idx.is_some() {
                if defaults[defaults_i] == serde_json::Value::Null {
                    panic!("Missing `default` for argument idx {args_i}");
                }
                args[args_i] = defaults[defaults_i].clone();
            }
        } else if first_non_null_optional_idx.is_none() {
            first_non_null_optional_idx = Some(args_i);
        }
    }

    let required_num = args.len() - defaults.len();

    if let Some(i) = first_non_null_optional_idx {
        &args[..i + 1]
    } else {
        &args[..required_num]
    }
}

/// Convert a possible-null result into an Option.
fn opt_result<T: for<'a> serde::de::Deserialize<'a>>(
    result: serde_json::Value,
) -> Result<Option<T>> {
    if result == serde_json::Value::Null {
        Ok(None)
    } else {
        Ok(serde_json::from_value(result)?)
    }
}

/// Used to pass raw txs into the API.
pub trait RawTx: Sized + Clone {
    fn raw_hex(self) -> String;
}

impl RawTx for &Transaction {
    fn raw_hex(self) -> String {
        encode::serialize_hex(self)
    }
}

impl RawTx for &[u8] {
    fn raw_hex(self) -> String {
        self.to_lower_hex_string()
    }
}

impl RawTx for &Vec<u8> {
    fn raw_hex(self) -> String {
        self.to_lower_hex_string()
    }
}

impl RawTx for &str {
    fn raw_hex(self) -> String {
        self.to_owned()
    }
}

impl RawTx for String {
    fn raw_hex(self) -> String {
        self
    }
}

/// The different authentication methods for the client.
#[derive(Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub enum Auth {
    None,
    Basic {
        username: String,
        password: String,
    },
    CookieFile(PathBuf),
    Bearer(String),
}

impl Auth {
    /// Inserts appropriate headers into the provided HeaderMap based on the authentication method.
    pub fn auth(self, headers: &mut HeaderMap) -> Result<()> {
        match self {
            Auth::None => Ok(()), // No headers needed
            Auth::Basic {
                username,
                password,
            } => {
                let encoded = general_purpose::STANDARD.encode(format!("{username}:{password}"));
                let auth_value = format!("Basic {encoded}");
                headers.insert(
                    header::AUTHORIZATION,
                    // TODO: use error propagation
                    HeaderValue::from_str(&auth_value).unwrap(),
                );
                Ok(())
            }
            Auth::CookieFile(path) => {
                let line = BufReader::new(File::open(path)?)
                    .lines()
                    .next()
                    .ok_or(Error::InvalidCookieFile)??;
                let colon = line.find(':').ok_or(Error::InvalidCookieFile)?;
                let username = &line[..colon];
                let password = &line[colon + 1..];
                let encoded = general_purpose::STANDARD.encode(format!("{username}:{password}",));
                let auth_value = format!("Basic {encoded}");
                // TODO: use error propagation
                headers.insert(header::AUTHORIZATION, HeaderValue::from_str(&auth_value).unwrap());
                Ok(())
            }
            Auth::Bearer(token) => {
                let auth_value = format!("Bearer {token}");
                // TODO: use error propagation
                headers.insert(header::AUTHORIZATION, HeaderValue::from_str(&auth_value).unwrap());
                Ok(())
            }
        }
    }
}

#[async_trait::async_trait]
#[allow(clippy::too_many_arguments)]
pub trait RpcApi: Sized {
    /// Call a `cmd` rpc with given `args` list
    async fn call<T: for<'de> serde::de::Deserialize<'de>>(
        &self,
        method: &str,
        params: &[serde_json::Value],
    ) -> Result<T>;

    /// Query an object implementing `Querable` type
    async fn get_by_id<T: queryable::Queryable<Self>>(
        &self,
        id: &<T as queryable::Queryable<Self>>::Id,
    ) -> Result<T>
    where
        <T as queryable::Queryable<Self>>::Id: Sync,
    {
        T::query(self, id).await
    }

    async fn get_network_info(&self) -> Result<bitcoin_json::GetNetworkInfoResult> {
        self.call("getnetworkinfo", NOPARAMS).await
    }

    async fn get_index_info(&self) -> Result<bitcoin_json::GetIndexInfoResult> {
        self.call("getindexinfo", NOPARAMS).await
    }

    async fn version(&self) -> Result<usize> {
        #[derive(Deserialize)]
        struct Response {
            pub version: usize,
        }
        let res: Response = self.call("getnetworkinfo", NOPARAMS).await?;
        Ok(res.version)
    }

    async fn add_multisig_address(
        &self,
        nrequired: usize,
        keys: &[bitcoin_json::PubKeyOrAddress],
        label: Option<&str>,
        address_type: Option<bitcoin_json::AddressType>,
    ) -> Result<bitcoin_json::AddMultiSigAddressResult> {
        let mut args = [
            into_json(nrequired)?,
            into_json(keys)?,
            opt_into_json(label)?,
            opt_into_json(address_type)?,
        ];
        self.call(
            "addmultisigaddress",
            handle_defaults(&mut args, [into_json("")?, null()].as_slice()),
        )
        .await
    }

    async fn load_wallet(&self, wallet: &str) -> Result<bitcoin_json::LoadWalletResult> {
        self.call("loadwallet", [wallet.into()].as_slice()).await
    }

    async fn unload_wallet(
        &self,
        wallet: Option<&str>,
    ) -> Result<Option<bitcoin_json::UnloadWalletResult>> {
        let mut args = [opt_into_json(wallet)?];
        self.call("unloadwallet", handle_defaults(&mut args, [null()].as_slice())).await
    }

    async fn create_wallet(
        &self,
        wallet: &str,
        disable_private_keys: Option<bool>,
        blank: Option<bool>,
        passphrase: Option<&str>,
        avoid_reuse: Option<bool>,
    ) -> Result<bitcoin_json::LoadWalletResult> {
        let mut args = [
            wallet.into(),
            opt_into_json(disable_private_keys)?,
            opt_into_json(blank)?,
            opt_into_json(passphrase)?,
            opt_into_json(avoid_reuse)?,
        ];
        self.call(
            "createwallet",
            handle_defaults(
                &mut args,
                [false.into(), false.into(), into_json("")?, false.into()].as_slice(),
            ),
        )
        .await
    }

    async fn list_wallets(&self) -> Result<Vec<String>> {
        self.call("listwallets", NOPARAMS).await
    }

    async fn list_wallet_dir(&self) -> Result<Vec<String>> {
        let result: bitcoin_json::ListWalletDirResult =
            self.call("listwalletdir", NOPARAMS).await?;
        let names = result.wallets.into_iter().map(|x| x.name).collect();
        Ok(names)
    }

    async fn get_wallet_info(&self) -> Result<bitcoin_json::GetWalletInfoResult> {
        self.call("getwalletinfo", NOPARAMS).await
    }

    async fn backup_wallet(&self, destination: Option<&str>) -> Result<()> {
        let mut args = [opt_into_json(destination)?];
        self.call("backupwallet", handle_defaults(&mut args, [null()].as_slice())).await
    }

    async fn dump_private_key(&self, address: &Address) -> Result<PrivateKey> {
        self.call("dumpprivkey", [address.to_string().into()].as_slice()).await
    }

    async fn encrypt_wallet(&self, passphrase: &str) -> Result<()> {
        self.call("encryptwallet", [into_json(passphrase)?].as_slice()).await
    }

    async fn get_difficulty(&self) -> Result<f64> {
        self.call("getdifficulty", NOPARAMS).await
    }

    async fn get_connection_count(&self) -> Result<usize> {
        self.call("getconnectioncount", NOPARAMS).await
    }

    async fn get_block(&self, hash: &bitcoin::BlockHash) -> Result<Block> {
        let hex: String = self.call("getblock", [into_json(hash)?, 0.into()].as_slice()).await?;
        Ok(encode::deserialize_hex(&hex)?)
    }

    async fn get_block_hex(&self, hash: &bitcoin::BlockHash) -> Result<String> {
        self.call("getblock", [into_json(hash)?, 0.into()].as_slice()).await
    }

    async fn get_block_info(
        &self,
        hash: &bitcoin::BlockHash,
    ) -> Result<bitcoin_json::GetBlockResult> {
        self.call("getblock", [into_json(hash)?, 1.into()].as_slice()).await
    }

    //TODO(stevenroose) add getblock_txs

    async fn get_block_header(&self, hash: &bitcoin::BlockHash) -> Result<bitcoin::block::Header> {
        let hex: String =
            self.call("getblockheader", [into_json(hash)?, false.into()].as_slice()).await?;
        Ok(encode::deserialize_hex(&hex)?)
    }

    async fn get_block_header_info(
        &self,
        hash: &bitcoin::BlockHash,
    ) -> Result<bitcoin_json::GetBlockHeaderResult> {
        self.call("getblockheader", [into_json(hash)?, true.into()].as_slice()).await
    }

    async fn get_mining_info(&self) -> Result<bitcoin_json::GetMiningInfoResult> {
        self.call("getmininginfo", NOPARAMS).await
    }

    async fn get_block_template(
        &self,
        mode: bitcoin_json::GetBlockTemplateModes,
        rules: &[bitcoin_json::GetBlockTemplateRules],
        capabilities: &[bitcoin_json::GetBlockTemplateCapabilities],
    ) -> Result<bitcoin_json::GetBlockTemplateResult> {
        #[derive(Serialize)]
        struct Argument<'a> {
            mode: bitcoin_json::GetBlockTemplateModes,
            rules: &'a [bitcoin_json::GetBlockTemplateRules],
            capabilities: &'a [bitcoin_json::GetBlockTemplateCapabilities],
        }

        self.call(
            "getblocktemplate",
            [into_json(Argument {
                mode,
                rules,
                capabilities,
            })?]
            .as_slice(),
        )
        .await
    }

    /// Returns a data structure containing various state info regarding
    /// blockchain processing.
    async fn get_blockchain_info(&self) -> Result<bitcoin_json::GetBlockchainInfoResult> {
        let mut raw: serde_json::Value = self.call("getblockchaininfo", NOPARAMS).await?;
        // The softfork fields are not backwards compatible:
        // - 0.18.x returns a "softforks" array and a "bip9_softforks" map.
        // - 0.19.x returns a "softforks" map.
        Ok(if self.version().await? < 190000 {
            use crate::Error::UnexpectedStructure as err;

            // First, remove both incompatible softfork fields.
            // We need to scope the mutable ref here for v1.29 borrowck.
            let (bip9_softforks, old_softforks) = {
                let map = raw.as_object_mut().ok_or(err)?;
                let bip9_softforks = map.remove("bip9_softforks").ok_or(err)?;
                let old_softforks = map.remove("softforks").ok_or(err)?;
                // Put back an empty "softforks" field.
                map.insert("softforks".into(), serde_json::Map::new().into());
                (bip9_softforks, old_softforks)
            };
            let mut ret: bitcoin_json::GetBlockchainInfoResult = serde_json::from_value(raw)?;

            // Then convert both softfork types and add them.
            for sf in old_softforks.as_array().ok_or(err)?.iter() {
                let json = sf.as_object().ok_or(err)?;
                let id = json.get("id").ok_or(err)?.as_str().ok_or(err)?;
                let reject = json.get("reject").ok_or(err)?.as_object().ok_or(err)?;
                let active = reject.get("status").ok_or(err)?.as_bool().ok_or(err)?;
                ret.softforks.insert(
                    id.into(),
                    bitcoin_json::Softfork {
                        type_: bitcoin_json::SoftforkType::Buried,
                        bip9: None,
                        height: None,
                        active,
                    },
                );
            }
            for (id, sf) in bip9_softforks.as_object().ok_or(err)?.iter() {
                #[derive(Deserialize)]
                struct OldBip9SoftFork {
                    pub status: bitcoin_json::Bip9SoftforkStatus,
                    pub bit: Option<u8>,
                    #[serde(rename = "startTime")]
                    pub start_time: i64,
                    pub timeout: u64,
                    pub since: u32,
                    pub statistics: Option<bitcoin_json::Bip9SoftforkStatistics>,
                }
                let sf: OldBip9SoftFork = serde_json::from_value(sf.clone())?;
                ret.softforks.insert(
                    id.clone(),
                    bitcoin_json::Softfork {
                        type_: bitcoin_json::SoftforkType::Bip9,
                        bip9: Some(bitcoin_json::Bip9SoftforkInfo {
                            status: sf.status,
                            bit: sf.bit,
                            start_time: sf.start_time,
                            timeout: sf.timeout,
                            since: sf.since,
                            statistics: sf.statistics,
                        }),
                        height: None,
                        active: sf.status == bitcoin_json::Bip9SoftforkStatus::Active,
                    },
                );
            }
            ret
        } else {
            serde_json::from_value(raw)?
        })
    }

    /// Returns the numbers of block in the longest chain.
    async fn get_block_count(&self) -> Result<u64> {
        self.call("getblockcount", NOPARAMS).await
    }

    /// Returns the hash of the best (tip) block in the longest blockchain.
    async fn get_best_block_hash(&self) -> Result<bitcoin::BlockHash> {
        self.call("getbestblockhash", NOPARAMS).await
    }

    /// Get block hash at a given height
    async fn get_block_hash(&self, height: u64) -> Result<bitcoin::BlockHash> {
        self.call("getblockhash", [height.into()].as_slice()).await
    }

    async fn get_block_stats(&self, height: u64) -> Result<bitcoin_json::GetBlockStatsResult> {
        self.call("getblockstats", [height.into()].as_slice()).await
    }

    async fn get_block_stats_fields(
        &self,
        height: u64,
        fields: &[bitcoin_json::BlockStatsFields],
    ) -> Result<bitcoin_json::GetBlockStatsResultPartial> {
        self.call("getblockstats", [height.into(), fields.into()].as_slice()).await
    }

    async fn get_raw_transaction(
        &self,
        txid: &bitcoin::Txid,
        block_hash: Option<&bitcoin::BlockHash>,
    ) -> Result<Transaction> {
        let mut args = [into_json(txid)?, into_json(false)?, opt_into_json(block_hash)?];
        let hex: String =
            self.call("getrawtransaction", handle_defaults(&mut args, [null()].as_slice())).await?;
        Ok(encode::deserialize_hex(&hex)?)
    }

    async fn get_raw_transaction_hex(
        &self,
        txid: &bitcoin::Txid,
        block_hash: Option<&bitcoin::BlockHash>,
    ) -> Result<String> {
        let mut args = [into_json(txid)?, into_json(false)?, opt_into_json(block_hash)?];
        self.call("getrawtransaction", handle_defaults(&mut args, [null()].as_slice())).await
    }

    async fn get_raw_transaction_info(
        &self,
        txid: &bitcoin::Txid,
        block_hash: Option<&bitcoin::BlockHash>,
    ) -> Result<bitcoin_json::GetRawTransactionResult> {
        let mut args = [into_json(txid)?, into_json(true)?, opt_into_json(block_hash)?];
        self.call("getrawtransaction", handle_defaults(&mut args, [null()].as_slice())).await
    }

    async fn get_block_filter(
        &self,
        block_hash: &bitcoin::BlockHash,
    ) -> Result<bitcoin_json::GetBlockFilterResult> {
        self.call("getblockfilter", [into_json(block_hash)?].as_slice()).await
    }

    async fn get_balance(
        &self,
        minconf: Option<usize>,
        include_watchonly: Option<bool>,
    ) -> Result<Amount> {
        let mut args = ["*".into(), opt_into_json(minconf)?, opt_into_json(include_watchonly)?];
        Ok(Amount::from_btc(
            self.call("getbalance", handle_defaults(&mut args, [0.into(), null()].as_slice()))
                .await?,
        )?)
    }

    async fn get_balances(&self) -> Result<bitcoin_json::GetBalancesResult> {
        self.call("getbalances", NOPARAMS).await
    }

    async fn get_received_by_address(
        &self,
        address: &Address,
        minconf: Option<u32>,
    ) -> Result<Amount> {
        let mut args = [address.to_string().into(), opt_into_json(minconf)?];
        Ok(Amount::from_btc(
            self.call("getreceivedbyaddress", handle_defaults(&mut args, [null()].as_slice()))
                .await?,
        )?)
    }

    async fn get_transaction(
        &self,
        txid: &bitcoin::Txid,
        include_watchonly: Option<bool>,
    ) -> Result<bitcoin_json::GetTransactionResult> {
        let mut args = [into_json(txid)?, opt_into_json(include_watchonly)?];
        self.call("gettransaction", handle_defaults(&mut args, [null()].as_slice())).await
    }

    async fn list_transactions(
        &self,
        label: Option<&str>,
        count: Option<usize>,
        skip: Option<usize>,
        include_watchonly: Option<bool>,
    ) -> Result<Vec<bitcoin_json::ListTransactionResult>> {
        let mut args = [
            label.unwrap_or("*").into(),
            opt_into_json(count)?,
            opt_into_json(skip)?,
            opt_into_json(include_watchonly)?,
        ];
        self.call(
            "listtransactions",
            handle_defaults(&mut args, [10.into(), 0.into(), null()].as_slice()),
        )
        .await
    }

    async fn list_since_block(
        &self,
        blockhash: Option<&bitcoin::BlockHash>,
        target_confirmations: Option<usize>,
        include_watchonly: Option<bool>,
        include_removed: Option<bool>,
    ) -> Result<bitcoin_json::ListSinceBlockResult> {
        let mut args = [
            opt_into_json(blockhash)?,
            opt_into_json(target_confirmations)?,
            opt_into_json(include_watchonly)?,
            opt_into_json(include_removed)?,
        ];
        self.call("listsinceblock", handle_defaults(&mut args, [null()].as_slice())).await
    }

    async fn get_tx_out(
        &self,
        txid: &bitcoin::Txid,
        vout: u32,
        include_mempool: Option<bool>,
    ) -> Result<Option<bitcoin_json::GetTxOutResult>> {
        let mut args = [into_json(txid)?, into_json(vout)?, opt_into_json(include_mempool)?];
        opt_result(self.call("gettxout", handle_defaults(&mut args, [null()].as_slice())).await?)
    }

    async fn get_tx_out_proof(
        &self,
        txids: &[bitcoin::Txid],
        block_hash: Option<&bitcoin::BlockHash>,
    ) -> Result<Vec<u8>> {
        let mut args = [into_json(txids)?, opt_into_json(block_hash)?];
        let hex: String =
            self.call("gettxoutproof", handle_defaults(&mut args, [null()].as_slice())).await?;
        // TODO: What is that fromhex
        Ok(FromHex::from_hex(&hex)?)
    }

    async fn import_public_key(
        &self,
        pubkey: &PublicKey,
        label: Option<&str>,
        rescan: Option<bool>,
    ) -> Result<()> {
        let mut args = [pubkey.to_string().into(), opt_into_json(label)?, opt_into_json(rescan)?];
        self.call("importpubkey", handle_defaults(&mut args, [into_json("")?, null()].as_slice()))
            .await
    }

    async fn import_private_key(
        &self,
        privkey: &PrivateKey,
        label: Option<&str>,
        rescan: Option<bool>,
    ) -> Result<()> {
        let mut args = [privkey.to_string().into(), opt_into_json(label)?, opt_into_json(rescan)?];
        self.call("importprivkey", handle_defaults(&mut args, [into_json("")?, null()].as_slice()))
            .await
    }

    async fn import_address(
        &self,
        address: &Address,
        label: Option<&str>,
        rescan: Option<bool>,
    ) -> Result<()> {
        let mut args = [address.to_string().into(), opt_into_json(label)?, opt_into_json(rescan)?];
        self.call("importaddress", handle_defaults(&mut args, [into_json("")?, null()].as_slice()))
            .await
    }

    async fn import_address_script(
        &self,
        script: &Script,
        label: Option<&str>,
        rescan: Option<bool>,
        p2sh: Option<bool>,
    ) -> Result<()> {
        let mut args = [
            script.to_hex_string().into(),
            opt_into_json(label)?,
            opt_into_json(rescan)?,
            opt_into_json(p2sh)?,
        ];
        self.call(
            "importaddress",
            handle_defaults(&mut args, [into_json("")?, true.into(), null()].as_slice()),
        )
        .await
    }

    async fn import_multi(
        &self,
        requests: &[bitcoin_json::ImportMultiRequest],
        options: Option<&bitcoin_json::ImportMultiOptions>,
    ) -> Result<Vec<bitcoin_json::ImportMultiResult>> {
        let mut json_requests = Vec::with_capacity(requests.len());
        for req in requests {
            json_requests.push(serde_json::to_value(req)?);
        }
        let mut args = [json_requests.into(), opt_into_json(options)?];
        self.call("importmulti", handle_defaults(&mut args, [null()].as_slice())).await
    }

    async fn import_descriptors(
        &self,
        req: bitcoin_json::ImportDescriptors,
    ) -> Result<Vec<bitcoin_json::ImportMultiResult>> {
        let json_request = vec![serde_json::to_value(req)?];
        self.call(
            "importdescriptors",
            handle_defaults(&mut [json_request.into()], [null()].as_slice()),
        )
        .await
    }

    async fn set_label(&self, address: &Address, label: &str) -> Result<()> {
        self.call("setlabel", [address.to_string().into(), label.into()].as_slice()).await
    }

    async fn key_pool_refill(&self, new_size: Option<usize>) -> Result<()> {
        let mut args = [opt_into_json(new_size)?];
        self.call("keypoolrefill", handle_defaults(&mut args, [null()].as_slice())).await
    }

    async fn list_unspent(
        &self,
        minconf: Option<usize>,
        maxconf: Option<usize>,
        addresses: Option<&[&Address<NetworkChecked>]>,
        include_unsafe: Option<bool>,
        query_options: Option<bitcoin_json::ListUnspentQueryOptions>,
    ) -> Result<Vec<bitcoin_json::ListUnspentResultEntry>> {
        let mut args = [
            opt_into_json(minconf)?,
            opt_into_json(maxconf)?,
            opt_into_json(addresses)?,
            opt_into_json(include_unsafe)?,
            opt_into_json(query_options)?,
        ];
        let defaults = [into_json(0)?, into_json(9999999)?, empty_arr(), into_json(true)?, null()];
        self.call("listunspent", handle_defaults(&mut args, defaults.as_slice())).await
    }

    /// To unlock, use [unlock_unspent].
    async fn lock_unspent(&self, outputs: &[OutPoint]) -> Result<bool> {
        let outputs: Vec<_> =
            outputs.iter().map(|o| serde_json::to_value(JsonOutPoint::from(*o)).unwrap()).collect();
        self.call("lockunspent", [false.into(), outputs.into()].as_slice()).await
    }

    async fn unlock_unspent(&self, outputs: &[OutPoint]) -> Result<bool> {
        let outputs: Vec<_> =
            outputs.iter().map(|o| serde_json::to_value(JsonOutPoint::from(*o)).unwrap()).collect();
        self.call("lockunspent", [true.into(), outputs.into()].as_slice()).await
    }

    /// Unlock all unspent UTXOs.
    async fn unlock_unspent_all(&self) -> Result<bool> {
        self.call("lockunspent", [true.into()].as_slice()).await
    }

    async fn list_received_by_address(
        &self,
        address_filter: Option<&Address>,
        minconf: Option<u32>,
        include_empty: Option<bool>,
        include_watchonly: Option<bool>,
    ) -> Result<Vec<bitcoin_json::ListReceivedByAddressResult>> {
        let mut args = [
            opt_into_json(minconf)?,
            opt_into_json(include_empty)?,
            opt_into_json(include_watchonly)?,
            opt_into_json(address_filter)?,
        ];
        let defaults = [1.into(), false.into(), false.into(), null()];
        self.call("listreceivedbyaddress", handle_defaults(&mut args, defaults.as_slice())).await
    }

    async fn create_psbt(
        &self,
        inputs: &[bitcoin_json::CreateRawTransactionInput],
        outputs: &HashMap<String, Amount>,
        locktime: Option<i64>,
        replaceable: Option<bool>,
    ) -> Result<String> {
        let outs_converted = serde_json::Map::from_iter(
            outputs.iter().map(|(k, v)| (k.clone(), serde_json::Value::from(v.to_btc()))),
        );
        self.call(
            "createpsbt",
            [
                into_json(inputs)?,
                into_json(outs_converted)?,
                into_json(locktime)?,
                into_json(replaceable)?,
            ]
            .as_slice(),
        )
        .await
    }

    async fn create_raw_transaction_hex(
        &self,
        utxos: &[bitcoin_json::CreateRawTransactionInput],
        outs: &HashMap<String, Amount>,
        locktime: Option<i64>,
        replaceable: Option<bool>,
    ) -> Result<String> {
        let outs_converted = serde_json::Map::from_iter(
            outs.iter().map(|(k, v)| (k.clone(), serde_json::Value::from(v.to_btc()))),
        );
        let mut args = [
            into_json(utxos)?,
            into_json(outs_converted)?,
            opt_into_json(locktime)?,
            opt_into_json(replaceable)?,
        ];
        let defaults = [into_json(0i64)?, null()];
        self.call("createrawtransaction", handle_defaults(&mut args, defaults.as_slice())).await
    }

    async fn create_raw_transaction(
        &self,
        utxos: &[bitcoin_json::CreateRawTransactionInput],
        outs: &HashMap<String, Amount>,
        locktime: Option<i64>,
        replaceable: Option<bool>,
    ) -> Result<Transaction> {
        let hex: String =
            self.create_raw_transaction_hex(utxos, outs, locktime, replaceable).await?;
        Ok(encode::deserialize_hex(&hex)?)
    }

    async fn decode_raw_transaction<R: RawTx + Send>(
        &self,
        tx: R,
        is_witness: Option<bool>,
    ) -> Result<bitcoin_json::DecodeRawTransactionResult> {
        let mut args = [tx.raw_hex().into(), opt_into_json(is_witness)?];
        let defaults = [null()];
        self.call("decoderawtransaction", handle_defaults(&mut args, defaults.as_slice())).await
    }

    async fn fund_raw_transaction<R: RawTx + Send>(
        &self,
        tx: R,
        options: Option<&bitcoin_json::FundRawTransactionOptions>,
        is_witness: Option<bool>,
    ) -> Result<bitcoin_json::FundRawTransactionResult> {
        let mut args = [tx.raw_hex().into(), opt_into_json(options)?, opt_into_json(is_witness)?];
        let defaults = [empty_obj(), null()];
        self.call("fundrawtransaction", handle_defaults(&mut args, defaults.as_slice())).await
    }

    #[deprecated]
    async fn sign_raw_transaction<R: RawTx + Send>(
        &self,
        tx: R,
        utxos: Option<&[bitcoin_json::SignRawTransactionInput]>,
        private_keys: Option<&[PrivateKey]>,
        sighash_type: Option<bitcoin_json::SigHashType>,
    ) -> Result<bitcoin_json::SignRawTransactionResult> {
        let mut args = [
            tx.raw_hex().into(),
            opt_into_json(utxos)?,
            opt_into_json(private_keys)?,
            opt_into_json(sighash_type)?,
        ];
        let defaults = [empty_arr(), empty_arr(), null()];
        self.call("signrawtransaction", handle_defaults(&mut args, defaults.as_slice())).await
    }

    async fn sign_raw_transaction_with_wallet<R: RawTx + Send>(
        &self,
        tx: R,
        utxos: Option<&[bitcoin_json::SignRawTransactionInput]>,
        sighash_type: Option<bitcoin_json::SigHashType>,
    ) -> Result<bitcoin_json::SignRawTransactionResult> {
        let mut args = [tx.raw_hex().into(), opt_into_json(utxos)?, opt_into_json(sighash_type)?];
        let defaults = [empty_arr(), null()];
        self.call("signrawtransactionwithwallet", handle_defaults(&mut args, defaults.as_slice()))
            .await
    }

    async fn sign_raw_transaction_with_key<R: RawTx + Send>(
        &self,
        tx: R,
        privkeys: &[PrivateKey],
        prevtxs: Option<&[bitcoin_json::SignRawTransactionInput]>,
        sighash_type: Option<bitcoin_json::SigHashType>,
    ) -> Result<bitcoin_json::SignRawTransactionResult> {
        let mut args = [
            tx.raw_hex().into(),
            into_json(privkeys)?,
            opt_into_json(prevtxs)?,
            opt_into_json(sighash_type)?,
        ];
        let defaults = [empty_arr(), null()];
        self.call("signrawtransactionwithkey", handle_defaults(&mut args, defaults.as_slice()))
            .await
    }

    async fn test_mempool_accept<R: RawTx + Sync>(
        &self,
        rawtxs: &[R],
    ) -> Result<Vec<bitcoin_json::TestMempoolAcceptResult>> {
        let hexes: Vec<serde_json::Value> =
            rawtxs.iter().cloned().map(|r| r.raw_hex().into()).collect();
        self.call("testmempoolaccept", [hexes.into()].as_slice()).await
    }

    async fn stop(&self) -> Result<String> {
        self.call("stop", NOPARAMS).await
    }

    async fn verify_message(
        &self,
        address: &Address,
        signature: &Signature,
        message: &str,
    ) -> Result<bool> {
        let args = [address.to_string().into(), signature.to_string().into(), into_json(message)?];
        self.call("verifymessage", args.as_slice()).await
    }

    /// Generate new address under own control
    async fn get_new_address(
        &self,
        label: Option<&str>,
        address_type: Option<bitcoin_json::AddressType>,
    ) -> Result<Address<NetworkUnchecked>> {
        self.call("getnewaddress", [opt_into_json(label)?, opt_into_json(address_type)?].as_slice())
            .await
    }

    /// Generate new address for receiving change
    async fn get_raw_change_address(
        &self,
        address_type: Option<bitcoin_json::AddressType>,
    ) -> Result<Address<NetworkUnchecked>> {
        self.call("getrawchangeaddress", [opt_into_json(address_type)?].as_slice()).await
    }

    async fn get_address_info(
        &self,
        address: &Address,
    ) -> Result<bitcoin_json::GetAddressInfoResult> {
        self.call("getaddressinfo", [address.to_string().into()].as_slice()).await
    }

    /// Mine `block_num` blocks and pay coinbase to `address`
    ///
    /// Returns hashes of the generated blocks
    async fn generate_to_address(
        &self,
        block_num: u64,
        address: &Address<NetworkChecked>,
    ) -> Result<Vec<bitcoin::BlockHash>> {
        self.call("generatetoaddress", [block_num.into(), address.to_string().into()].as_slice())
            .await
    }

    /// Mine up to block_num blocks immediately (before the RPC call returns)
    /// to an address in the wallet.
    async fn generate(
        &self,
        block_num: u64,
        maxtries: Option<u64>,
    ) -> Result<Vec<bitcoin::BlockHash>> {
        self.call("generate", [block_num.into(), opt_into_json(maxtries)?].as_slice()).await
    }

    /// Mark a block as invalid by `block_hash`
    async fn invalidate_block(&self, block_hash: &bitcoin::BlockHash) -> Result<()> {
        self.call("invalidateblock", [into_json(block_hash)?].as_slice()).await
    }

    /// Mark a block as valid by `block_hash`
    async fn reconsider_block(&self, block_hash: &bitcoin::BlockHash) -> Result<()> {
        self.call("reconsiderblock", [into_json(block_hash)?].as_slice()).await
    }

    /// Returns details on the active state of the TX memory pool
    async fn get_mempool_info(&self) -> Result<bitcoin_json::GetMempoolInfoResult> {
        self.call("getmempoolinfo", NOPARAMS).await
    }

    /// Get txids of all transactions in a memory pool
    async fn get_raw_mempool(&self) -> Result<Vec<bitcoin::Txid>> {
        self.call("getrawmempool", NOPARAMS).await
    }

    /// Get details for the transactions in a memory pool
    async fn get_raw_mempool_verbose(
        &self,
    ) -> Result<HashMap<bitcoin::Txid, bitcoin_json::GetMempoolEntryResult>> {
        self.call("getrawmempool", [into_json(true)?].as_slice()).await
    }

    /// Get mempool data for given transaction
    async fn get_mempool_entry(
        &self,
        txid: &bitcoin::Txid,
    ) -> Result<bitcoin_json::GetMempoolEntryResult> {
        self.call("getmempoolentry", [into_json(txid)?].as_slice()).await
    }

    /// Get information about all known tips in the block tree, including the
    /// main chain as well as stale branches.
    async fn get_chain_tips(&self) -> Result<bitcoin_json::GetChainTipsResult> {
        self.call("getchaintips", NOPARAMS).await
    }

    async fn send_to_address(
        &self,
        address: &Address<NetworkChecked>,
        amount: Amount,
        comment: Option<&str>,
        comment_to: Option<&str>,
        subtract_fee: Option<bool>,
        replaceable: Option<bool>,
        confirmation_target: Option<u32>,
        estimate_mode: Option<bitcoin_json::EstimateMode>,
    ) -> Result<bitcoin::Txid> {
        let mut args = [
            address.to_string().into(),
            into_json(amount.to_btc())?,
            opt_into_json(comment)?,
            opt_into_json(comment_to)?,
            opt_into_json(subtract_fee)?,
            opt_into_json(replaceable)?,
            opt_into_json(confirmation_target)?,
            opt_into_json(estimate_mode)?,
        ];
        self.call(
            "sendtoaddress",
            handle_defaults(
                &mut args,
                ["".into(), "".into(), false.into(), false.into(), 6.into(), null()].as_slice(),
            ),
        )
        .await
    }

    /// Attempts to add a node to the addnode list.
    /// Nodes added using addnode (or -connect) are protected from DoS disconnection and are not required to be full nodes/support SegWit as other outbound peers are (though such peers will not be synced from).
    async fn add_node(&self, addr: &str) -> Result<()> {
        self.call("addnode", [into_json(addr)?, into_json("add")?].as_slice()).await
    }

    /// Attempts to remove a node from the addnode list.
    async fn remove_node(&self, addr: &str) -> Result<()> {
        self.call("addnode", [into_json(addr)?, into_json("remove")?].as_slice()).await
    }

    /// Attempts to connect to a node without permanently adding it to the addnode list.
    async fn onetry_node(&self, addr: &str) -> Result<()> {
        self.call("addnode", [into_json(addr)?, into_json("onetry")?].as_slice()).await
    }

    /// Immediately disconnects from the specified peer node.
    async fn disconnect_node(&self, addr: &str) -> Result<()> {
        self.call("disconnectnode", [into_json(addr)?].as_slice()).await
    }

    async fn disconnect_node_by_id(&self, node_id: u32) -> Result<()> {
        self.call("disconnectnode", [into_json("")?, into_json(node_id)?].as_slice()).await
    }

    /// Returns information about the given added node, or all added nodes (note that onetry addnodes are not listed here)
    async fn get_added_node_info(
        &self,
        node: Option<&str>,
    ) -> Result<Vec<bitcoin_json::GetAddedNodeInfoResult>> {
        if let Some(addr) = node {
            self.call("getaddednodeinfo", [into_json(addr)?].as_slice()).await
        } else {
            self.call("getaddednodeinfo", NOPARAMS).await
        }
    }

    /// Return known addresses which can potentially be used to find new nodes in the network
    async fn get_node_addresses(
        &self,
        count: Option<usize>,
    ) -> Result<Vec<bitcoin_json::GetNodeAddressesResult>> {
        let cnt = count.unwrap_or(1);
        self.call("getnodeaddresses", [into_json(cnt)?].as_slice()).await
    }

    /// List all banned IPs/Subnets.
    async fn list_banned(&self) -> Result<Vec<bitcoin_json::ListBannedResult>> {
        self.call("listbanned", NOPARAMS).await
    }

    /// Clear all banned IPs.
    async fn clear_banned(&self) -> Result<()> {
        self.call("clearbanned", NOPARAMS).await
    }

    /// Attempts to add an IP/Subnet to the banned list.
    async fn add_ban(&self, subnet: &str, bantime: u64, absolute: bool) -> Result<()> {
        self.call(
            "setban",
            [into_json(subnet)?, into_json("add")?, into_json(bantime)?, into_json(absolute)?]
                .as_slice(),
        )
        .await
    }

    /// Attempts to remove an IP/Subnet from the banned list.
    async fn remove_ban(&self, subnet: &str) -> Result<()> {
        self.call("setban", [into_json(subnet)?, into_json("remove")?].as_slice()).await
    }

    /// Disable/enable all p2p network activity.
    async fn set_network_active(&self, state: bool) -> Result<bool> {
        self.call("setnetworkactive", [into_json(state)?].as_slice()).await
    }

    /// Returns data about each connected network node as an array of
    /// [`PeerInfo`].as_slice()[]
    ///
    /// [`PeerInfo`].as_slice(): net/struct.PeerInfo.html
    async fn get_peer_info(&self) -> Result<Vec<bitcoin_json::GetPeerInfoResult>> {
        self.call("getpeerinfo", NOPARAMS).await
    }

    /// Requests that a ping be sent to all other nodes, to measure ping
    /// time.
    ///
    /// Results provided in `getpeerinfo`, `pingtime` and `pingwait` fields
    /// are decimal seconds.
    ///
    /// Ping command is handled in queue with all other commands, so it
    /// measures processing backlog, not just network ping.
    async fn ping(&self) -> Result<()> {
        self.call("ping", NOPARAMS).await
    }

    async fn send_raw_transaction<R: RawTx + Send>(&self, tx: R) -> Result<bitcoin::Txid> {
        self.call("sendrawtransaction", [tx.raw_hex().into()].as_slice()).await
    }

    async fn estimate_smart_fee(
        &self,
        conf_target: u16,
        estimate_mode: Option<bitcoin_json::EstimateMode>,
    ) -> Result<bitcoin_json::EstimateSmartFeeResult> {
        let mut args = [into_json(conf_target)?, opt_into_json(estimate_mode)?];
        self.call("estimatesmartfee", handle_defaults(&mut args, [null()].as_slice())).await
    }

    /// Waits for a specific new block and returns useful info about it.
    /// Returns the current block on timeout or exit.
    ///
    /// # Arguments
    ///
    /// 1. `timeout`: Time in milliseconds to wait for a response. 0
    /// indicates no timeout.
    async fn wait_for_new_block(&self, timeout: u64) -> Result<bitcoin_json::BlockRef> {
        self.call("waitfornewblock", [into_json(timeout)?].as_slice()).await
    }

    /// Waits for a specific new block and returns useful info about it.
    /// Returns the current block on timeout or exit.
    ///
    /// # Arguments
    ///
    /// 1. `blockhash`: Block hash to wait for.
    /// 2. `timeout`: Time in milliseconds to wait for a response. 0
    /// indicates no timeout.
    async fn wait_for_block(
        &self,
        blockhash: &bitcoin::BlockHash,
        timeout: u64,
    ) -> Result<bitcoin_json::BlockRef> {
        let args = [into_json(blockhash)?, into_json(timeout)?];
        self.call("waitforblock", args.as_slice()).await
    }

    async fn wallet_create_funded_psbt(
        &self,
        inputs: &[bitcoin_json::CreateRawTransactionInput],
        outputs: &HashMap<String, Amount>,
        locktime: Option<i64>,
        options: Option<bitcoin_json::WalletCreateFundedPsbtOptions>,
        bip32derivs: Option<bool>,
    ) -> Result<bitcoin_json::WalletCreateFundedPsbtResult> {
        let outputs_converted = serde_json::Map::from_iter(
            outputs.iter().map(|(k, v)| (k.clone(), serde_json::Value::from(v.to_btc()))),
        );
        let mut args = [
            into_json(inputs)?,
            into_json(outputs_converted)?,
            opt_into_json(locktime)?,
            opt_into_json(options)?,
            opt_into_json(bip32derivs)?,
        ];
        self.call(
            "walletcreatefundedpsbt",
            handle_defaults(
                &mut args,
                [0.into(), serde_json::Map::new().into(), false.into()].as_slice(),
            ),
        )
        .await
    }

    async fn wallet_process_psbt(
        &self,
        psbt: &str,
        sign: Option<bool>,
        sighash_type: Option<bitcoin_json::SigHashType>,
        bip32derivs: Option<bool>,
    ) -> Result<bitcoin_json::WalletProcessPsbtResult> {
        let mut args = [
            into_json(psbt)?,
            opt_into_json(sign)?,
            opt_into_json(sighash_type)?,
            opt_into_json(bip32derivs)?,
        ];
        let defaults = [
            true.into(),
            into_json(bitcoin_json::SigHashType::from(
                bitcoin::sighash::EcdsaSighashType::All,
            ))?,
            true.into(),
        ];
        self.call("walletprocesspsbt", handle_defaults(&mut args, defaults.as_slice())).await
    }

    async fn get_descriptor_info(
        &self,
        desc: &str,
    ) -> Result<bitcoin_json::GetDescriptorInfoResult> {
        self.call("getdescriptorinfo", [desc.to_string().into()].as_slice()).await
    }

    async fn join_psbt(&self, psbts: &[String]) -> Result<String> {
        self.call("joinpsbts", [into_json(psbts)?].as_slice()).await
    }

    async fn combine_psbt(&self, psbts: &[String]) -> Result<String> {
        self.call("combinepsbt", [into_json(psbts)?].as_slice()).await
    }

    async fn combine_raw_transaction(&self, hex_strings: &[String]) -> Result<String> {
        self.call("combinerawtransaction", [into_json(hex_strings)?].as_slice()).await
    }

    async fn finalize_psbt(
        &self,
        psbt: &str,
        extract: Option<bool>,
    ) -> Result<bitcoin_json::FinalizePsbtResult> {
        let mut args = [into_json(psbt)?, opt_into_json(extract)?];
        self.call("finalizepsbt", handle_defaults(&mut args, [true.into()].as_slice())).await
    }

    async fn derive_addresses(
        &self,
        descriptor: &str,
        range: Option<[u32; 2]>,
    ) -> Result<Vec<Address<NetworkUnchecked>>> {
        let mut args = [into_json(descriptor)?, opt_into_json(range)?];
        self.call("deriveaddresses", handle_defaults(&mut args, [null()].as_slice())).await
    }

    async fn rescan_blockchain(
        &self,
        start_from: Option<usize>,
        stop_height: Option<usize>,
    ) -> Result<(usize, Option<usize>)> {
        let mut args = [opt_into_json(start_from)?, opt_into_json(stop_height)?];

        #[derive(Deserialize)]
        struct Response {
            pub start_height: usize,
            pub stop_height: Option<usize>,
        }
        let res: Response = self
            .call("rescanblockchain", handle_defaults(&mut args, [0.into(), null()].as_slice()))
            .await?;
        Ok((res.start_height, res.stop_height))
    }

    /// Returns statistics about the unspent transaction output set.
    /// Note this call may take some time if you are not using coinstatsindex..await
    async fn get_tx_out_set_info(
        &self,
        hash_type: Option<bitcoin_json::TxOutSetHashType>,
        hash_or_height: Option<bitcoin_json::HashOrHeight>,
        use_index: Option<bool>,
    ) -> Result<bitcoin_json::GetTxOutSetInfoResult> {
        let mut args =
            [opt_into_json(hash_type)?, opt_into_json(hash_or_height)?, opt_into_json(use_index)?];
        self.call(
            "gettxoutsetinfo",
            handle_defaults(&mut args, [null(), null(), null()].as_slice()),
        )
        .await
    }

    /// Returns information about network traffic, including bytes in, bytes out,
    /// and current time.
    async fn get_net_totals(&self) -> Result<bitcoin_json::GetNetTotalsResult> {
        self.call("getnettotals", NOPARAMS).await
    }

    /// Returns the estimated network hashes per second based on the last n blocks.
    async fn get_network_hash_ps(&self, nblocks: Option<u64>, height: Option<u64>) -> Result<f64> {
        let mut args = [opt_into_json(nblocks)?, opt_into_json(height)?];
        self.call("getnetworkhashps", handle_defaults(&mut args, [null(), null()].as_slice())).await
    }

    /// Returns the total uptime of the server in seconds
    async fn uptime(&self) -> Result<u64> {
        self.call("uptime", NOPARAMS).await
    }

    /// Submit a block
    async fn submit_block(&self, block: &bitcoin::Block) -> Result<()> {
        let block_hex: String = bitcoin::consensus::encode::serialize_hex(block);
        self.submit_block_hex(&block_hex).await
    }

    /// Submit a raw block
    async fn submit_block_bytes(&self, block_bytes: &[u8]) -> Result<()> {
        let block_hex: String = block_bytes.to_lower_hex_string();
        self.submit_block_hex(&block_hex).await
    }

    /// Submit a block as a hex string
    async fn submit_block_hex(&self, block_hex: &str) -> Result<()> {
        match self.call("submitblock", [into_json(block_hex)?].as_slice()).await {
            Ok(serde_json::Value::Null) => Ok(()),
            Ok(res) => Err(Error::ReturnedError(res.to_string())),
            Err(err) => Err(err),
        }
    }

    async fn scan_tx_out_set_blocking(
        &self,
        descriptors: &[bitcoin_json::ScanTxOutRequest],
    ) -> Result<bitcoin_json::ScanTxOutResult> {
        self.call("scantxoutset", ["start".into(), into_json(descriptors)?].as_slice()).await
    }

    /// Returns information about the active ZeroMQ notifications
    async fn get_zmq_notifications(
        &self,
    ) -> Result<Vec<bitcoin_json::GetZmqNotificationsResult>> {
        self.call("getzmqnotifications", NOPARAMS).await
    }
}

/// Client implements a JSON-RPC client for the Bitcoin Core daemon or compatible APIs.
#[derive(Clone)]
pub struct Client {
    client: jsonrpsee::http_client::HttpClient,
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "bitcoincore_rpc::Client(HttpClient)")
    }
}

impl Client {
    /// Create a new JSON-RPC client to the bitcoind node using HTTPS or HTTP.
    pub fn new(url: &str, auth: Option<Auth>) -> Result<Self> {
        let mut builder = jsonrpsee::http_client::HttpClientBuilder::default();

        if let Some(auth) = auth {
            let mut headers = HeaderMap::new();
            auth.auth(&mut headers)?;
            builder = builder.set_headers(headers);
        }

        let client = builder.build(url)?;
        Ok(Client {
            client,
        })
    }
}

#[async_trait::async_trait]
impl RpcApi for Client {
    async fn call<T: for<'de> serde::de::Deserialize<'de>>(
        &self,
        method: &str,
        params: &[serde_json::Value],
    ) -> Result<T> {
        let mut params_arr = ArrayParams::new();
        for p in params {
            params_arr.insert(p)?;
        }
        let response = self.client.request(method, params_arr).await?;
        Ok(response)
    }
}

// fn log_response(cmd: &str, resp: &Result<jsonrpc::Response>) {
//     if log_enabled!(Warn) || log_enabled!(Debug) || log_enabled!(Trace) {
//         match resp {
//             Err(ref e) => {
//                 if log_enabled!(Debug) {
//                     debug!(target: "bitcoincore_rpc", "JSON-RPC failed parsing reply of {}: {:?}", cmd, e);
//                 }
//             }
//             Ok(ref resp) => {
//                 if let Some(ref e) = resp.error {
//                     if log_enabled!(Debug) {
//                         debug!(target: "bitcoincore_rpc", "JSON-RPC error for {}: {:?}", cmd, e);
//                     }
//                 } else if log_enabled!(Trace) {
//                     let def =
//                         serde_json::value::to_raw_value(&serde_json::value::Value::Null).unwrap();
//                     let result = resp.result.as_ref().unwrap_or(&def);
//                     trace!(target: "bitcoincore_rpc", "JSON-RPC response for {}: {}", cmd, result);
//                 }
//             }
//         }
//     }
// }

#[cfg(test)]
mod tests {
    // use super::*;
    // use crate::bitcoin;
    // use serde_json;
    //
    // #[test]
    // fn test_raw_tx() {
    //     use crate::bitcoin::consensus::encode;
    //     let client = Client::new("http://localhost/".into(), Auth::None).unwrap();
    //     let tx: bitcoin::Transaction = encode::deserialize(&Vec::<u8>::from_hex("0200000001586bd02815cf5faabfec986a4e50d25dbee089bd2758621e61c5fab06c334af0000000006b483045022100e85425f6d7c589972ee061413bcf08dc8c8e589ce37b217535a42af924f0e4d602205c9ba9cb14ef15513c9d946fa1c4b797883e748e8c32171bdf6166583946e35c012103dae30a4d7870cd87b45dd53e6012f71318fdd059c1c2623b8cc73f8af287bb2dfeffffff021dc4260c010000001976a914f602e88b2b5901d8aab15ebe4a97cf92ec6e03b388ac00e1f505000000001976a914687ffeffe8cf4e4c038da46a9b1d37db385a472d88acfd211500").unwrap()).unwrap();
    //
    //     assert!(client.send_raw_transaction(&tx).is_err());
    //     assert!(client.send_raw_transaction(&encode::serialize(&tx)).is_err());
    //     assert!(client.send_raw_transaction("deadbeef").is_err());
    //     assert!(client.send_raw_transaction("deadbeef".to_owned()).is_err());
    // }
    //
    // fn test_handle_defaults_inner() -> Result<()> {
    //     {
    //         let mut args = [into_json(0)?, null(), null()];
    //         let defaults = [into_json(1)?, into_json(2)?];
    //         let res = [into_json(0)?];
    //         assert_eq!(handle_defaults(&mut args, &defaults), &res);
    //     }
    //     {
    //         let mut args = [into_json(0)?, into_json(1)?, null()];
    //         let defaults = [into_json(2)?];
    //         let res = [into_json(0)?, into_json(1)?];
    //         assert_eq!(handle_defaults(&mut args, &defaults), &res);
    //     }
    //     {
    //         let mut args = [into_json(0)?, null(), into_json(5)?];
    //         let defaults = [into_json(2)?, into_json(3)?];
    //         let res = [into_json(0)?, into_json(2)?, into_json(5)?];
    //         assert_eq!(handle_defaults(&mut args, &defaults), &res);
    //     }
    //     {
    //         let mut args = [into_json(0)?, null(), into_json(5)?, null()];
    //         let defaults = [into_json(2)?, into_json(3)?, into_json(4)?];
    //         let res = [into_json(0)?, into_json(2)?, into_json(5)?];
    //         assert_eq!(handle_defaults(&mut args, &defaults), &res);
    //     }
    //     {
    //         let mut args = [null(), null()];
    //         let defaults = [into_json(2)?, into_json(3)?];
    //         let res: [serde_json::Value; 0] = [];
    //         assert_eq!(handle_defaults(&mut args, &defaults), &res);
    //     }
    //     {
    //         let mut args = [null(), into_json(1)?];
    //         let defaults = [];
    //         let res = [null(), into_json(1)?];
    //         assert_eq!(handle_defaults(&mut args, &defaults), &res);
    //     }
    //     {
    //         let mut args = [];
    //         let defaults = [];
    //         let res: [serde_json::Value; 0] = [];
    //         assert_eq!(handle_defaults(&mut args, &defaults), &res);
    //     }
    //     {
    //         let mut args = [into_json(0)?];
    //         let defaults = [into_json(2)?];
    //         let res = [into_json(0)?];
    //         assert_eq!(handle_defaults(&mut args, &defaults), &res);
    //     }
    //     Ok(())
    // }
    //
    // #[test]
    // fn test_handle_defaults() {
    //     test_handle_defaults_inner().unwrap();
    // }
    //
    // #[test]
    // fn auth_cookie_file_ignores_newline() {
    //     let tempdir = tempfile::tempdir().unwrap();
    //     let path = tempdir.path().join("cookie");
    //     std::fs::write(&path, "foo:bar\n").unwrap();
    //     assert_eq!(
    //         Auth::CookieFile(path).get_user_pass().unwrap(),
    //         (Some("foo".into()), Some("bar".into())),
    //     );
    // }
    //
    // #[test]
    // fn auth_cookie_file_ignores_additional_lines() {
    //     let tempdir = tempfile::tempdir().unwrap();
    //     let path = tempdir.path().join("cookie");
    //     std::fs::write(&path, "foo:bar\nbaz").unwrap();
    //     assert_eq!(
    //         Auth::CookieFile(path).get_user_pass().unwrap(),
    //         (Some("foo".into()), Some("bar".into())),
    //     );
    // }
    //
    // #[test]
    // fn auth_cookie_file_fails_if_colon_isnt_present() {
    //     let tempdir = tempfile::tempdir().unwrap();
    //     let path = tempdir.path().join("cookie");
    //     std::fs::write(&path, "foobar").unwrap();
    //     assert!(matches!(Auth::CookieFile(path).get_user_pass(), Err(Error::InvalidCookieFile)));
    // }
}
