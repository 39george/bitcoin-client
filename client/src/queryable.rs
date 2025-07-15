use crate::client::Result;
use crate::client::RpcApi;

/// A type that can be queried from Bitcoin Core.
#[async_trait::async_trait]
pub trait Queryable<C: RpcApi>: Sized {
    /// Type of the ID used to query the item.
    type Id;
    /// Query the item using `rpc` and convert to `Self`.
    async fn query(rpc: &C, id: &Self::Id) -> Result<Self>;
}

#[async_trait::async_trait]
impl<C: RpcApi + Sync> Queryable<C> for bitcoin::block::Block {
    type Id = bitcoin::BlockHash;

    async fn query(rpc: &C, id: &Self::Id) -> Result<Self> {
        let rpc_name = "getblock";
        let hex: String =
            rpc.call(rpc_name, [serde_json::to_value(id)?, 0.into()].as_slice()).await?;
        Ok(bitcoin::consensus::encode::deserialize_hex(&hex)?)
    }
}

#[async_trait::async_trait]
impl<C: RpcApi + Sync> Queryable<C> for bitcoin::transaction::Transaction {
    type Id = bitcoin::Txid;

    async fn query(rpc: &C, id: &Self::Id) -> Result<Self> {
        let rpc_name = "getrawtransaction";
        let hex: String = rpc.call(rpc_name, [serde_json::to_value(id)?].as_slice()).await?;
        Ok(bitcoin::consensus::encode::deserialize_hex(&hex)?)
    }
}

#[async_trait::async_trait]
impl<C: RpcApi + Sync> Queryable<C> for Option<bitcoin_rpc_json::GetTxOutResult> {
    type Id = bitcoin::OutPoint;

    async fn query(rpc: &C, id: &Self::Id) -> Result<Self> {
        rpc.get_tx_out(&id.txid, id.vout, Some(true)).await
    }
}
