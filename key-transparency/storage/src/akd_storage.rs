use crate::Storage;
use vkd::{
    errors::StorageError as AkdStorageError,
    storage::{
        transaction::Transaction,
        types::{
            AkdLabel, AkdValue, DbRecord, KeyData, ValueState, ValueStateKey,
            ValueStateRetrievalFlag,
        },
        Storable as AkdStorable,
    },
};
use async_trait::async_trait;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;

pub struct AkdStorage {
    database: Arc<RwLock<Storage>>,
    transaction: Transaction,
}

impl AkdStorage {
    pub fn new(path: &str) -> Self {
        let storage = Storage::new(path).expect("Failed to initialize inner storage");
        Self {
            database: Arc::new(RwLock::new(storage)),
            transaction: Transaction::new(),
        }
    }
}

impl Clone for AkdStorage {
    fn clone(&self) -> Self {
        Self {
            database: self.database.clone(),
            transaction: Transaction::new(),
        }
    }
}

#[async_trait]
impl vkd::storage::Storage for AkdStorage {
    async fn log_metrics(&self, _level: log::Level) {
       self.database.read().await.log_metrics();
    }

    async fn begin_transaction(&self) -> bool {
        self.transaction.begin_transaction().await
    }

    async fn commit_transaction(&self) -> Result<(), AkdStorageError> {
        let operations = self.transaction.commit_transaction().await?;
        self.batch_set(operations).await
    }

    async fn rollback_transaction(&self) -> Result<(), AkdStorageError> {
        self.transaction.rollback_transaction().await
    }

    async fn is_transaction_active(&self) -> bool {
        self.transaction.is_transaction_active().await
    }

    async fn set(&self, record: DbRecord) -> Result<(), AkdStorageError> {
        if self.is_transaction_active().await {
            self.transaction.set(&record).await;
            return Ok(());
        }

        let serialized = match bincode::serialize(&record) {
            Ok(x) => x,
            Err(e) => {
                let error = format!("Serialization error: {}", e);
                return Err(AkdStorageError::Other(error));
            }
        };
        let guard = self.database.write().await;
        guard
            .write(&record.get_full_binary_id(), &serialized)
            .map_err(|e| AkdStorageError::Other(format!("Failed to persist record: {}", e)))
    }

    async fn batch_set(&self, records: Vec<DbRecord>) -> Result<(), AkdStorageError> {
        // TODO: This is really bad, we may end up with partial writes in case of failure.
        for record in records {
            self.set(record).await?;
        }
        Ok(())
    }

    async fn get<St: AkdStorable>(&self, id: &St::Key) -> Result<DbRecord, AkdStorageError> {
        if self.is_transaction_active().await {
            if let Some(result) = self.transaction.get::<St>(id).await {
                return Ok(result);
            }
        }

        let binary_id = St::get_full_binary_key_id(id);
        let guard = self.database.read().await;
        match (*guard).read(&binary_id) {
            Ok(Some(bytes)) => bincode::deserialize(&bytes)
                .map_err(|e| AkdStorageError::Other(format!("Serialization error: {}", e))),
            Ok(None) => Err(AkdStorageError::NotFound("Not found".to_string())),
            Err(e) => Err(AkdStorageError::Other(format!("{}", e))),
        }
    }

    async fn batch_get<St: AkdStorable>(
        &self,
        ids: &[St::Key],
    ) -> Result<Vec<DbRecord>, AkdStorageError> {
        let mut map = Vec::new();
        for key in ids.iter() {
            if let Ok(result) = self.get::<St>(key).await {
                map.push(result);
            }
        }
        Ok(map)
    }

    async fn get_direct<St: AkdStorable>(&self, id: &St::Key) -> Result<DbRecord, AkdStorageError> {
        AkdStorage::get::<St>(self, id).await
    }

    async fn flush_cache(&self) {
        self.database.read().await.flush_cache();
    }

    async fn get_user_data(&self, _username: &AkdLabel) -> Result<KeyData, AkdStorageError> {
        unimplemented!()
    }

    async fn get_user_state(
        &self,
        _username: &AkdLabel,
        _flag: ValueStateRetrievalFlag,
    ) -> Result<ValueState, AkdStorageError> {
        unimplemented!()
    }

    async fn get_user_state_versions(
        &self,
        _usernames: &[AkdLabel],
        _flag: ValueStateRetrievalFlag,
    ) -> Result<HashMap<AkdLabel, (u64, AkdValue)>, AkdStorageError> {
        Ok(HashMap::new())
    }

    async fn tombstone_value_states(&self, _keys: &[ValueStateKey]) -> Result<(), AkdStorageError> {
        unimplemented!()
    }
}
