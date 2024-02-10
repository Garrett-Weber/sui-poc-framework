use std::{collections::BTreeMap, num::NonZeroUsize, path::PathBuf, str::FromStr as _};

use fastcrypto::traits::AllowedRng;
use rand::rngs::ThreadRng;
use tokio::runtime::Runtime;

use simulacrum::Simulacrum;
use sui_json_rpc_types::{SuiObjectData, SuiObjectResponseQuery};
use sui_keys::keystore::{AccountKeystore as _, InMemKeystore};
use sui_protocol_config::ProtocolConfig;
use sui_sdk::{rpc_types::SuiObjectDataOptions, SuiClient};
use sui_swarm_config::network_config_builder::ConfigBuilder;
use sui_types::{
    base_types::{ObjectID, SequenceNumber, SuiAddress},
    coin::Coin,
    crypto::{AccountKeyPair, AuthorityQuorumSignInfo, KeypairTraits, SuiKeyPair},
    digests::TransactionDigest,
    effects::TransactionEffects,
    error::ExecutionError,
    gas_coin::{self, MIST_PER_SUI},
    message_envelope::VerifiedEnvelope,
    messages_checkpoint::CheckpointSummary,
    object::Object,
    sui_system_state::epoch_start_sui_system_state::EpochStartSystemState,
};

pub struct Environment<R = ThreadRng> {
    sim: Simulacrum<R>,
    keys: Vec<sui_types::crypto::AccountKeyPair>,
}

impl Environment {
    /// Create EnvironmentBuilder with default rng.
    pub fn builder() -> EnvironmentBuilder<ThreadRng> {
        EnvironmentBuilder::new(ThreadRng::default())
    }
}

impl<R: AllowedRng + Clone> Environment<R> {
    /// Create EnvironmentBuilder with given rng.
    pub fn builder_with_rng(rng: R) -> EnvironmentBuilder<R> {
        EnvironmentBuilder::new(rng)
    }

    pub fn random_keypair(&mut self) -> AccountKeyPair {
        sui_types::crypto::get_key_pair_from_rng(self.sim.rng()).1
    }
}

impl<R> Environment<R> {
    pub fn funder_keypair(&self) -> Option<AccountKeyPair> {
        self.sim
            .keystore()
            .accounts()
            .next()
            .and_then(|acc| Some(acc.1.copy()))
    }

    pub fn keypair(&self, n: u8) -> AccountKeyPair {
        self.keys[n as usize].copy()
    }

    /// Get an in-memory keystore. Alias for keys are numbered from "0" to "255" with "sponsor" as the funder.
    pub fn key_store(&self) -> anyhow::Result<InMemKeystore> {
        let mut keystore = InMemKeystore::default();
        for i in 0..=255 {
            let key = self.keypair(i);
            keystore.add_key(Some(i.to_string()), SuiKeyPair::Ed25519(key))?;
        }

        match self.funder_keypair() {
            Some(funder) => {
                keystore.add_key(Some("sponsor".to_string()), SuiKeyPair::Ed25519(funder))?;
                Ok(keystore)
            }
            None => Err(anyhow::anyhow!("no funder key found")),
        }
    }

    /// Fund public key from funder account.
    pub fn fund_key(
        &mut self,
        address: sui_types::base_types::SuiAddress,
    ) -> anyhow::Result<TransactionEffects> {
        self.sim.request_gas(address, MIST_PER_SUI)
    }

    pub fn get_balance(&self, address: sui_types::base_types::SuiAddress) -> u64 {
        self.sim
            .store()
            .owned_objects(address)
            .filter(|obj| obj.is_gas_coin())
            .map(|obj| obj.get_coin_value_unsafe())
            .sum()
    }

    /// Get balance for specific coin.
    pub fn get_coin_balance(
        &self,
        owner: sui_types::base_types::SuiAddress,
        coin_id: ObjectID,
    ) -> u64 {
        self.sim
            .store()
            .owned_objects(owner)
            .filter(|obj| obj.is_coin() && (coin_id == *obj.as_coin_maybe().unwrap().id()))
            .map(|obj| obj.get_coin_value_unsafe())
            .sum()
    }

    /// Get object in global store.
    pub fn get_object(&self, object_id: &ObjectID) -> anyhow::Result<Option<Object>> {
        Ok(self.sim.store().backing_store().get_object(object_id)?)
    }

    pub fn get_object_with_sequence(
        &self,
        object_id: &ObjectID,
        sequence_number: SequenceNumber,
    ) -> anyhow::Result<Option<Object>> {
        Ok(self
            .sim
            .store()
            .backing_store()
            .get_object_by_key(object_id, sequence_number)?)
    }

    /// Get all objects owned by an address.
    pub fn get_owned_objects(&self, owner: sui_types::base_types::SuiAddress) -> Vec<Object> {
        self.sim.store().owned_objects(owner).collect::<Vec<_>>()
    }

    /// Get all coins owned by an address.
    pub fn get_all_owned_coins(&self, owner: sui_types::base_types::SuiAddress) -> Vec<Coin> {
        self.sim
            .store()
            .owned_objects(owner)
            .filter_map(|obj| obj.as_coin_maybe())
            .collect::<Vec<_>>()
    }

    /// Get all specific coins owned by an address.
    pub fn get_owned_coins(
        &self,
        owner: sui_types::base_types::SuiAddress,
        coin_id: ObjectID,
    ) -> Vec<Coin> {
        self.sim
            .store()
            .owned_objects(owner)
            .filter_map(|obj| obj.as_coin_maybe())
            .filter(|coin| coin.id.id.bytes == coin_id)
            .collect::<Vec<_>>()
    }

    /// Get all gas coins owned by an address.
    pub fn get_owned_sui(&self, owner: sui_types::base_types::SuiAddress) -> Vec<Coin> {
        self.sim
            .store()
            .owned_objects(owner)
            .filter(|obj| obj.is_gas_coin())
            .map(|obj| obj.as_coin_maybe().unwrap())
            .collect::<Vec<_>>()
    }

    /// Get object owned by funder keypair that can be used in funding transactions.
    pub fn get_funder_gas_object(&self) -> anyhow::Result<Option<Object>> {
        match self.funder_keypair() {
            Some(funder) => {
                let funder_address = SuiAddress::from(funder.public());
                Ok(self
                    .get_owned_objects(funder_address)
                    .into_iter()
                    .find(|o| o.is_coin() && o.get_coin_value_unsafe() > (MIST_PER_SUI / 100)))
            }
            None => return Err(anyhow::anyhow!("No funder key found")),
        }
    }

    /// Get Epoch
    pub fn get_epoch(&self) -> &EpochStartSystemState {
        self.sim.epoch_start_state()
    }

    /// Execute transaction in simulator
    pub fn execute_transaction(
        &mut self,
        transaction: sui_types::transaction::Transaction,
    ) -> anyhow::Result<(TransactionEffects, Option<ExecutionError>)> {
        self.sim.execute_transaction(transaction)
    }

    /// Execute transaction in simulator and print debug info
    pub fn execute_transaction_debug(
        &mut self,
        transaction: sui_types::transaction::Transaction,
    ) -> anyhow::Result<(TransactionEffects, Option<ExecutionError>)> {
        let (effects, error) = self.sim.execute_transaction(transaction)?;
        println!(
            "Transaction Effects Summary: {:?}",
            effects.summary_for_debug()
        );

        let changed_objects = effects.all_changed_objects();
        println!("Changed Objects: {}", changed_objects.len());
        for (obj_ref, owner, change_kind) in changed_objects {
            println!(
                "Object: {:?}, Owner: {:?}, Change Kind: {:?}",
                obj_ref, owner, change_kind
            );
        }

        let deleted_objects = effects.all_removed_objects();
        println!("Deleted Objects: {}", deleted_objects.len());
        for (obj_ref, _remove_kind) in deleted_objects {
            println!("Object: {:?}", obj_ref);
        }
        Ok((effects, error))
    }

    /// Advance simulator clock by given duration.
    ///
    /// This creates and executes a ConsensusCommitPrologue transaction which advances the chain Clock by the provided duration.
    pub fn advance_clock(&mut self, duration: std::time::Duration) -> TransactionEffects {
        self.sim.advance_clock(duration)
    }

    /// Creates the next Checkpoint using the Transactions enqueued since the last checkpoint was created.
    pub fn create_checkpoint(
        &mut self,
    ) -> VerifiedEnvelope<CheckpointSummary, AuthorityQuorumSignInfo<true>> {
        self.sim.create_checkpoint()
    }

    /// Advances the epoch.
    ///
    /// This creates and executes an EndOfEpoch transaction which advances the chain into the next
    /// epoch. Since it is required to be the final transaction in an epoch, the final checkpoint in
    /// the epoch is also created.
    ///
    /// create_random_state controls whether a `RandomStateCreate` end of epoch transaction is
    /// included as part of this epoch change (to initialise on-chain randomness for the first
    /// time).
    ///
    /// NOTE: This function does not currently support updating the protocol version or the system
    /// packages
    pub fn advance_epoch(&mut self, create_random_state: bool) {
        self.sim.advance_epoch(create_random_state)
    }
}

#[derive(Default)]
pub struct EnvironmentBuilder<R = ThreadRng> {
    rng: R,
    objects: BTreeMap<sui_types::base_types::ObjectID, sui_types::object::Object>,
    start_time_ms: u64,
}

impl<R: AllowedRng + Clone> EnvironmentBuilder<R> {
    fn new(rng: R) -> Self {
        let mut objects = BTreeMap::new();
        // Simulator automatically adds all builtin packages but publishing packages without all dependencies in global store will fail
        objects.extend(
            sui_framework::BuiltInFramework::iter_system_packages()
                .map(|p| (p.id, p.genesis_object())),
        );
        EnvironmentBuilder {
            rng,
            objects,
            start_time_ms: 1,
        }
    }

    /// Add 1 SUI to key.
    pub fn fund_key(&mut self, address: SuiAddress) -> &mut Self {
        self.fund_key_with_amount(address, gas_coin::MIST_PER_SUI)
    }

    /// Add amount in MIST to key.
    pub fn fund_key_with_amount(&mut self, address: SuiAddress, amount: u64) -> &mut Self {
        let object = Object::new_gas_with_balance_and_owner_for_testing(amount, address);
        self.objects.insert(object.id(), object);
        self
    }

    pub fn set_start_time(&mut self, start_time: u64) -> &mut Self {
        self.start_time_ms = start_time;
        self
    }

    pub fn set_start_epoch(&mut self, start_epoch: u64) -> &mut Self {
        self.start_time_ms = start_epoch * 1000;
        self
    }

    pub fn add_object(&mut self, object: Object) -> &mut Self {
        self.add_objects(vec![object])
    }

    pub fn add_objects(&mut self, objects: Vec<Object>) -> &mut Self {
        self.objects
            .extend(objects.into_iter().map(|o| (o.id(), o)));
        self
    }

    /// Publish package from local path. Publishes to Move.toml address.
    pub fn publish_package(&mut self, path: &str) -> anyhow::Result<&mut Self> {
        let move_build = sui_move_build::BuildConfig::default().build(PathBuf::from_str(path)?)?;

        let transitive_deps = move_build
            .get_dependency_original_package_ids()
            .into_iter()
            .filter_map(|obj_id| self.objects.get(&obj_id))
            .map(|o| o.data.try_as_package().unwrap())
            .collect::<Vec<_>>();

        let object = Object::new_package(
            &move_build.into_modules(),
            TransactionDigest::genesis_marker(),
            u64::MAX,
            transitive_deps,
        )?;

        if self.objects.contains_key(&object.id()) {
            return Err(anyhow::anyhow!("Object already exists"));
        }

        Ok(self.add_object(object))
    }

    /// Clone object from network.
    /// # Safety
    /// Due to an abudance of caution, Mysten uses an unnessary unsafe tag in a dependency function.
    /// This function should be regarded as safe.
    pub unsafe fn clone_object(
        &mut self,
        object_id: ObjectID,
        client: &SuiClient,
    ) -> anyhow::Result<&mut Self> {
        let rt = Runtime::new().unwrap();
        let object_data = match rt
            .block_on(
                client
                    .read_api()
                    .get_object_with_options(object_id, SuiObjectDataOptions::bcs_lossless()),
            )?
            .data
        {
            Some(object_data) => object_data,
            None => return Err(anyhow::anyhow!("Object not found")),
        };

        Ok(self.add_object(EnvironmentBuilder::object_data_to_object(object_data)?))
    }

    /// Clone objects from network.
    /// # Safety
    /// Due to an abudance of caution, Mysten uses an unnessary unsafe tag in a dependency function.
    /// This function should be regarded as safe.
    pub unsafe fn clone_objects(
        &mut self,
        object_ids: Vec<ObjectID>,
        client: &SuiClient,
    ) -> anyhow::Result<&mut Self> {
        let rt = Runtime::new().unwrap();
        let objects = rt
            .block_on(
                client.read_api().multi_get_object_with_options(
                    object_ids,
                    SuiObjectDataOptions::bcs_lossless(),
                ),
            )?
            .into_iter()
            .filter_map(|o| o.data)
            .map(|o| EnvironmentBuilder::object_data_to_object(o))
            .filter(|o| o.is_ok())
            .map(move |o| o.unwrap())
            .collect::<Vec<_>>();

        Ok(self.add_objects(objects))
    }

    /// Clone all objects owned by owner.
    /// # Safety
    /// Due to an abudance of caution, Mysten uses an unnessary unsafe tag in a dependency function.
    /// This function should be regarded as safe.
    pub unsafe fn clone_objects_from_owner(
        &mut self,
        owner: sui_types::base_types::SuiAddress,
        client: &SuiClient,
    ) -> anyhow::Result<&mut Self> {
        let rt = Runtime::new().unwrap();
        let mut objects: Vec<Object> = vec![];
        let mut cursor: Option<ObjectID> = None;

        loop {
            let response = rt.block_on(client.read_api().get_owned_objects(
                owner,
                Some(SuiObjectResponseQuery::new_with_options(
                    SuiObjectDataOptions::bcs_lossless(),
                )),
                cursor,
                None,
            ))?;
            cursor = response.next_cursor;
            objects.extend(
                response
                    .data
                    .into_iter()
                    .filter_map(|o| o.data)
                    .map(|o| EnvironmentBuilder::object_data_to_object(o))
                    .filter(|o| o.is_ok())
                    .map(|o| o.unwrap()),
            );

            if !response.has_next_page {
                break;
            }
        }
        Ok(self.add_objects(objects))
    }

    pub fn build(&mut self) -> Environment<R> {
        let keys = (0..=255)
            .map(|_| sui_types::crypto::get_key_pair_from_rng(&mut self.rng).1)
            .collect::<Vec<AccountKeyPair>>();

        let network_config = ConfigBuilder::new_with_temp_dir()
            .rng(&mut self.rng)
            .deterministic_committee_size(NonZeroUsize::MIN)
            .with_chain_start_timestamp_ms(self.start_time_ms)
            .build();
        let mut store = simulacrum::InMemoryStore::new(&network_config.genesis);

        store.update_objects(self.objects.to_owned(), vec![]);

        for key in keys.iter() {
            self.fund_key(SuiAddress::from(key.public()));
        }

        let sim = Simulacrum::<R>::new_with_network_config_store(
            &network_config,
            self.rng.to_owned(),
            store,
        );

        Environment { keys, sim }
    }
}

impl EnvironmentBuilder {
    unsafe fn object_data_to_object(object_data: SuiObjectData) -> anyhow::Result<Object> {
        if object_data.bcs.is_none() {
            return Err(anyhow::anyhow!("Object data did not contain bcs data"));
        }
        if object_data.owner.is_none() {
            return Err(anyhow::anyhow!("Object data did not contain owner"));
        }
        Ok(match object_data.bcs.unwrap() {
            sui_json_rpc_types::SuiRawData::MoveObject(raw_move_object) => {
                let object = sui_types::object::MoveObject::new_from_execution(
                    raw_move_object.type_.into(),
                    raw_move_object.has_public_transfer,
                    raw_move_object.version,
                    raw_move_object.bcs_bytes,
                    &ProtocolConfig::get_for_max_version_UNSAFE(),
                )?;
                Object::new_move(
                    object,
                    object_data.owner.unwrap(),
                    object_data.previous_transaction.unwrap_or_default(),
                )
            }
            sui_json_rpc_types::SuiRawData::Package(move_package) => {
                let package = sui_types::move_package::MovePackage::new(
                    move_package.id,
                    move_package.version,
                    move_package.module_map,
                    u64::MAX,
                    move_package.type_origin_table,
                    move_package.linkage_table,
                )?;

                Object::new_from_package(
                    package,
                    object_data.previous_transaction.unwrap_or_default(),
                )
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use rand::{rngs::OsRng, Rng, SeedableRng};
    use shared_crypto::intent::Intent;
    use std::str::FromStr;
    use std::sync::Mutex;
    use sui_keys::keystore::AccountKeystore;
    use sui_move_build::BuildConfig;
    use sui_sdk::SuiClientBuilder;
    use sui_types::{
        base_types::SuiAddress,
        clock::Clock,
        gas_coin::MIST_PER_SUI,
        id::UID,
        is_system_package,
        programmable_transaction_builder::ProgrammableTransactionBuilder,
        signature::GenericSignature,
        storage::WriteKind,
        sui_system_state::epoch_start_sui_system_state::EpochStartSystemStateTrait as _,
        transaction::{CallArg, ObjectArg, SenderSignedData, TransactionData},
        Identifier,
    };

    use super::*;

    lazy_static::lazy_static! {
        static ref PUBLISH_MUTEX: Mutex<()> = Mutex::new(());
    }

    #[test]
    fn build_env() {
        Environment::builder().build();
    }

    #[test]
    fn build_env_with_funds() {
        let address = SuiAddress::generate(OsRng);
        let env = Environment::builder().fund_key(address).build();

        let balance = env.get_balance(address);

        assert_eq!(balance, MIST_PER_SUI, "Fund key failed to add balance");
    }

    #[test]
    fn build_env_with_n_funds() {
        let address = SuiAddress::generate(OsRng);
        let amount: u64 = OsRng.gen_range(0..1000) * MIST_PER_SUI;

        let env = Environment::builder()
            .fund_key_with_amount(address, amount)
            .build();

        let balance = env.get_balance(address);

        assert_eq!(balance, amount, "Fund key failed to add n balance");
    }

    #[test]
    fn build_env_with_object() {
        let object = sui_types::object::generate_test_gas_objects()
            .pop()
            .unwrap();

        let env = Environment::builder().add_object(object.clone()).build();
        assert_eq!(
            env.get_object(&object.id()).unwrap().unwrap().data,
            object.data
        );
    }

    #[test]
    fn build_env_with_objects() {
        let objects = sui_types::object::generate_test_gas_objects();

        let env = Environment::builder()
            .add_objects(objects.to_owned())
            .build();
        for object in objects {
            assert_eq!(
                env.get_object(&object.id()).unwrap().unwrap().data,
                object.data
            );
        }
    }

    #[test]
    fn build_env_with_cloned_object() {
        let rt = Runtime::new().unwrap();
        let rpc_client = rt
            .block_on(SuiClientBuilder::default().build_devnet())
            .unwrap();
        let address = "0x0000000000000000000000000000000000000000000000000000000000000005"; // 0x5 SystemState
        let address = move_core_types::account_address::AccountAddress::from_str(address).unwrap();
        let object_id = ObjectID::from_address(address);

        let env: Environment = unsafe {
            Environment::builder()
                .clone_object(object_id, &rpc_client)
                .unwrap()
                .build()
        };

        assert!(
            env.get_object(&object_id).unwrap().is_some(),
            "Cloned object not found"
        );
    }

    #[test]
    fn build_env_with_cloned_package() {
        let rt = Runtime::new().unwrap();
        let rpc_client = rt
            .block_on(SuiClientBuilder::default().build_devnet())
            .unwrap();
        let address = "0x0000000000000000000000000000000000000000000000000000000000000003"; // SUI Consensus
        let address = move_core_types::account_address::AccountAddress::from_str(address).unwrap();
        let object_id = ObjectID::from_address(address);

        let env: Environment = unsafe {
            Environment::builder()
                .clone_object(object_id, &rpc_client)
                .unwrap()
                .build()
        };

        assert!(
            env.get_object(&object_id).unwrap().is_some(),
            "Cloned project not found"
        );
    }

    #[test]
    fn build_env_with_cloned_objects_from_owner() {
        let rt = Runtime::new().unwrap();
        let rpc_client = rt
            .block_on(SuiClientBuilder::default().build_devnet())
            .unwrap();

        let owner = "0x7d20dcdb2bca4f508ea9613994683eb4e76e9c4ed371169677c1be02aaf0b58e"; // faucet

        let owner = SuiAddress::from(
            move_core_types::account_address::AccountAddress::from_str(owner).unwrap(),
        );

        let env: Environment = unsafe {
            Environment::builder()
                .clone_objects_from_owner(owner, &rpc_client)
                .unwrap()
                .build()
        };

        let mut sum: usize = 0;
        let mut cursor = None;

        loop {
            let page = rt
                .block_on(
                    rpc_client
                        .read_api()
                        .get_owned_objects(owner, None, cursor, None),
                )
                .unwrap();
            sum += page.data.len();

            if !page.has_next_page {
                break;
            }
            cursor = page.next_cursor;
        }

        assert_eq!(
            sum,
            env.get_owned_objects(owner).len(),
            "Not all objects were cloned"
        );
    }

    #[test]
    fn build_env_with_published_package() {
        let _mutex = PUBLISH_MUTEX.lock().unwrap();
        let path = "tests/basics/";
        let env = Environment::builder()
            .publish_package(path)
            .unwrap()
            .build();

        for compiled_module in BuildConfig::default()
            .build((&path).into())
            .unwrap()
            .into_modules()
            .into_iter()
        {
            if is_system_package(*compiled_module.self_id().address()) {
                continue;
            }
            assert!(
                env.get_object(&ObjectID::from_address(
                    *compiled_module.self_id().address()
                ))
                .unwrap()
                .is_some(),
                "Package object not found"
            );
        }
    }

    #[test]
    fn deterministic_env() {
        let det_rng = rand::rngs::StdRng::from_seed([0; 32]);

        let mut env_a = Environment::builder_with_rng(det_rng.clone()).build();
        let mut env_b = Environment::builder_with_rng(det_rng).build();

        for i in 0..=255 {
            assert_eq!(
                env_a.keypair(i).public(),
                env_b.keypair(i).public(),
                "Deterministic keypairs found to be not equal"
            );
        }
        for _ in 0..=255 {
            assert_eq!(
                env_a.random_keypair(),
                env_b.random_keypair(),
                "Deterministic random keypairs found to be not equal"
            );
        }
    }

    #[test]
    fn random_env() {
        let mut env_a = Environment::builder().build();
        let mut env_b = Environment::builder().build();

        assert_ne!(
            env_a.keypair(1),
            env_b.keypair(1),
            "Non-deterministic keypairs are equal"
        );

        assert_ne!(
            env_a.random_keypair(),
            env_b.random_keypair(),
            "Non-deterministic random keypairs are equal"
        );
    }

    #[test]
    fn funder_balance() {
        let env = Environment::builder().build();
        let funder_address = SuiAddress::from(env.funder_keypair().unwrap().public());

        assert!(env.get_balance(funder_address) > 0, "Funder has no balance");
    }

    #[test]
    fn fund_keys() {
        let mut env = Environment::builder().build();
        let rand_address = SuiAddress::generate(OsRng);

        let before_balance = env.get_balance(rand_address);

        env.fund_key(rand_address).expect("Failed to fund key");

        let after_balance = env.get_balance(rand_address);

        assert_eq!(
            after_balance - before_balance,
            MIST_PER_SUI,
            "Fund key failed to add balance"
        );
    }

    #[test]
    fn send_sui() {
        let mut env = Environment::builder().build();
        let keystore = env.key_store().unwrap();
        let sender_address = keystore.get_address_by_alias("0".to_string()).unwrap();
        let recv_address = keystore.get_address_by_alias("1".to_string()).unwrap();
        let sponsor_address = SuiAddress::from(env.funder_keypair().unwrap().public());

        let before_balance = env.get_balance(*recv_address);

        let sponsor_obj = env.get_funder_gas_object().unwrap().unwrap();

        let mut tx_builder = ProgrammableTransactionBuilder::new();
        tx_builder.transfer_sui(*recv_address, Some(MIST_PER_SUI / 2));

        let ptx = tx_builder.finish();

        let tx_data = TransactionData::new_programmable_allow_sponsor(
            *sender_address,
            vec![(
                sponsor_obj.id(),
                sponsor_obj.as_inner().version(),
                sponsor_obj.as_inner().digest(),
            )],
            ptx,
            MIST_PER_SUI,
            env.sim.reference_gas_price(),
            sponsor_address,
        );

        let key_sig = keystore
            .sign_secure(&sender_address, &tx_data, Intent::sui_transaction())
            .unwrap();

        let sponsor_sig = keystore
            .sign_secure(&sponsor_address, &tx_data, Intent::sui_transaction())
            .unwrap();

        let tx = sui_types::transaction::Transaction::new(SenderSignedData::new(
            tx_data,
            Intent::sui_transaction(),
            vec![
                GenericSignature::Signature(key_sig),
                GenericSignature::Signature(sponsor_sig),
            ],
        ));

        assert!(
            env.execute_transaction(tx).unwrap().1.is_none(),
            "Transaction failed"
        );

        assert_eq!(
            env.get_balance(*recv_address),
            before_balance + (MIST_PER_SUI / 2),
            "Receiver has wrong balance after tx"
        );
    }

    #[ignore = "Devnet resets break this test"]
    #[test]
    fn interact_with_cloned_counter() {
        #[derive(Debug, serde::Deserialize)]
        struct Counter {
            _id: UID,
            owner: SuiAddress,
            value: u64,
        }

        let counter_value = 15u64;
        let rt = Runtime::new().unwrap();
        let rpc_client = rt
            .block_on(SuiClientBuilder::default().build_devnet())
            .unwrap();

        let counter_package = ObjectID::from_str(
            "0x49b128c9313e08490ead9d9ef5aeb02b9180d03a437c17c4361a63cf087dbc81",
        )
        .unwrap();
        let mut env = unsafe {
            Environment::builder()
                .clone_object(counter_package, &rpc_client)
                .unwrap()
                .build()
        };

        let keystore = env.key_store().unwrap();
        let sender_address = keystore.get_address_by_alias("0".to_string()).unwrap();
        let sponsor_address = SuiAddress::from(env.funder_keypair().unwrap().public());

        let sponsor_obj = env.get_funder_gas_object().unwrap().unwrap();

        let mut tx_builder = ProgrammableTransactionBuilder::new();
        tx_builder
            .move_call(
                counter_package,
                Identifier::from_str("counter").unwrap(),
                Identifier::from_str("create").unwrap(),
                vec![],
                vec![],
            )
            .unwrap();

        let ptx = tx_builder.finish();

        let tx_data = TransactionData::new_programmable_allow_sponsor(
            *sender_address,
            vec![(
                sponsor_obj.id(),
                sponsor_obj.as_inner().version(),
                sponsor_obj.as_inner().digest(),
            )],
            ptx,
            MIST_PER_SUI,
            env.sim.reference_gas_price(),
            sponsor_address,
        );

        let key_sig = keystore
            .sign_secure(&sender_address, &tx_data, Intent::sui_transaction())
            .unwrap();

        let sponsor_sig = keystore
            .sign_secure(&sponsor_address, &tx_data, Intent::sui_transaction())
            .unwrap();

        let tx = sui_types::transaction::Transaction::new(SenderSignedData::new(
            tx_data,
            Intent::sui_transaction(),
            vec![
                GenericSignature::Signature(key_sig),
                GenericSignature::Signature(sponsor_sig),
            ],
        ));

        let tx_result = env.execute_transaction(tx).unwrap();

        assert!(tx_result.1.is_none(), "Transaction failed");

        let counter_obj_id = tx_result
            .0
            .all_changed_objects()
            .into_iter()
            .find(|o| o.2 == WriteKind::Create)
            .unwrap()
            .0
             .0;

        let counter_obj = env.get_object(&counter_obj_id).unwrap().unwrap();

        let counter: Counter = counter_obj.to_rust().unwrap();

        assert_eq!(counter.owner, *sender_address, "Counter owner is incorrect");
        assert_eq!(counter.value, 0, "Counter value is incorrect");

        let sponsor_obj = env.get_funder_gas_object().unwrap().unwrap();

        let mut tx_builder = ProgrammableTransactionBuilder::new();
        tx_builder
            .move_call(
                counter_package,
                Identifier::from_str("counter").unwrap(),
                Identifier::from_str("set_value").unwrap(),
                vec![],
                vec![
                    CallArg::Object(ObjectArg::SharedObject {
                        id: counter_obj.id(),
                        initial_shared_version: counter_obj.version(),
                        mutable: true,
                    }),
                    CallArg::Pure(counter_value.to_le_bytes().to_vec()),
                ],
            )
            .unwrap();

        let ptx = tx_builder.finish();

        let tx_data = TransactionData::new_programmable_allow_sponsor(
            *sender_address,
            vec![(
                sponsor_obj.id(),
                sponsor_obj.as_inner().version(),
                sponsor_obj.as_inner().digest(),
            )],
            ptx,
            MIST_PER_SUI,
            env.sim.reference_gas_price(),
            sponsor_address,
        );

        let key_sig = keystore
            .sign_secure(&sender_address, &tx_data, Intent::sui_transaction())
            .unwrap();

        let sponsor_sig = keystore
            .sign_secure(&sponsor_address, &tx_data, Intent::sui_transaction())
            .unwrap();

        let tx = sui_types::transaction::Transaction::new(SenderSignedData::new(
            tx_data,
            Intent::sui_transaction(),
            vec![
                GenericSignature::Signature(key_sig),
                GenericSignature::Signature(sponsor_sig),
            ],
        ));

        let tx_result = env.execute_transaction(tx).unwrap();

        assert!(tx_result.1.is_none(), "Transaction failed");

        let counter_obj = env.get_object(&counter_obj_id).unwrap().unwrap();

        let counter: Counter = counter_obj.to_rust().unwrap();

        assert_eq!(counter.value, counter_value, "Counter value is incorrect");
    }

    #[test]
    fn interact_with_published_counter() {
        #[derive(Debug, serde::Deserialize)]
        struct Counter {
            _id: UID,
            owner: SuiAddress,
            value: u64,
        }

        let _mutex = PUBLISH_MUTEX.lock().unwrap();

        let path = "tests/basics/";
        let counter_value = 15u64;
        let counter_id = ObjectID::from_str("0x31337").unwrap();

        let mut env = Environment::builder()
            .publish_package(path)
            .unwrap()
            .build();

        let keystore = env.key_store().unwrap();
        let sender_address = keystore.get_address_by_alias("0".to_string()).unwrap();
        let sponsor_address = SuiAddress::from(env.funder_keypair().unwrap().public());

        let sponsor_obj = env.get_funder_gas_object().unwrap().unwrap();

        let mut tx_builder = ProgrammableTransactionBuilder::new();
        tx_builder
            .move_call(
                counter_id,
                Identifier::from_str("counter").unwrap(),
                Identifier::from_str("create").unwrap(),
                vec![],
                vec![],
            )
            .unwrap();

        let ptx = tx_builder.finish();

        let tx_data = TransactionData::new_programmable_allow_sponsor(
            *sender_address,
            vec![(
                sponsor_obj.id(),
                sponsor_obj.as_inner().version(),
                sponsor_obj.as_inner().digest(),
            )],
            ptx,
            MIST_PER_SUI,
            env.sim.reference_gas_price(),
            sponsor_address,
        );

        let key_sig = keystore
            .sign_secure(&sender_address, &tx_data, Intent::sui_transaction())
            .unwrap();

        let sponsor_sig = keystore
            .sign_secure(&sponsor_address, &tx_data, Intent::sui_transaction())
            .unwrap();

        let tx = sui_types::transaction::Transaction::new(SenderSignedData::new(
            tx_data,
            Intent::sui_transaction(),
            vec![
                GenericSignature::Signature(key_sig),
                GenericSignature::Signature(sponsor_sig),
            ],
        ));

        let tx_result = env.execute_transaction(tx).unwrap();

        let counter_obj_id = tx_result
            .0
            .all_changed_objects()
            .into_iter()
            .find(|o| o.2 == WriteKind::Create)
            .unwrap()
            .0
             .0;

        let counter_obj = env.get_object(&counter_obj_id).unwrap().unwrap();

        let counter: Counter = counter_obj.to_rust().unwrap();

        assert_eq!(counter.owner, *sender_address, "Counter owner is incorrect");
        assert_eq!(counter.value, 0, "Counter value is incorrect");

        let sponsor_obj = env.get_funder_gas_object().unwrap().unwrap();

        let mut tx_builder = ProgrammableTransactionBuilder::new();
        tx_builder
            .move_call(
                counter_id,
                Identifier::from_str("counter").unwrap(),
                Identifier::from_str("set_value").unwrap(),
                vec![],
                vec![
                    CallArg::Object(ObjectArg::SharedObject {
                        id: counter_obj.id(),
                        initial_shared_version: counter_obj.version(),
                        mutable: true,
                    }),
                    CallArg::Pure(counter_value.to_le_bytes().to_vec()),
                ],
            )
            .unwrap();

        let ptx = tx_builder.finish();

        let tx_data = TransactionData::new_programmable_allow_sponsor(
            *sender_address,
            vec![(
                sponsor_obj.id(),
                sponsor_obj.as_inner().version(),
                sponsor_obj.as_inner().digest(),
            )],
            ptx,
            MIST_PER_SUI,
            env.sim.reference_gas_price(),
            sponsor_address,
        );

        let key_sig = keystore
            .sign_secure(&sender_address, &tx_data, Intent::sui_transaction())
            .unwrap();

        let sponsor_sig = keystore
            .sign_secure(&sponsor_address, &tx_data, Intent::sui_transaction())
            .unwrap();

        let tx = sui_types::transaction::Transaction::new(SenderSignedData::new(
            tx_data,
            Intent::sui_transaction(),
            vec![
                GenericSignature::Signature(key_sig),
                GenericSignature::Signature(sponsor_sig),
            ],
        ));

        let tx_result = env.execute_transaction(tx).unwrap();

        assert!(tx_result.1.is_none(), "Transaction failed");

        let counter_obj = env.get_object(&counter_obj_id).unwrap().unwrap();

        let counter: Counter = counter_obj.to_rust().unwrap();

        assert_eq!(counter.value, counter_value, "Counter value is incorrect");
    }

    #[test]
    fn get_object_with_sequence_number() {
        let mut env = Environment::builder().build();
        let keystore = env.key_store().unwrap();
        let sender_address = keystore.get_address_by_alias("0".to_string()).unwrap();
        let recv_address = keystore.get_address_by_alias("1".to_string()).unwrap();
        let sponsor_address = SuiAddress::from(env.funder_keypair().unwrap().public());

        let sponsor_obj = env.get_funder_gas_object().unwrap().unwrap();

        let mut tx_builder = ProgrammableTransactionBuilder::new();
        tx_builder.transfer_sui(*recv_address, Some(MIST_PER_SUI / 2));

        let ptx = tx_builder.finish();

        let tx_data = TransactionData::new_programmable_allow_sponsor(
            *sender_address,
            vec![(
                sponsor_obj.id(),
                sponsor_obj.as_inner().version(),
                sponsor_obj.as_inner().digest(),
            )],
            ptx,
            MIST_PER_SUI,
            env.sim.reference_gas_price(),
            sponsor_address,
        );

        let key_sig = keystore
            .sign_secure(&sender_address, &tx_data, Intent::sui_transaction())
            .unwrap();

        let sponsor_sig = keystore
            .sign_secure(&sponsor_address, &tx_data, Intent::sui_transaction())
            .unwrap();

        let tx = sui_types::transaction::Transaction::new(SenderSignedData::new(
            tx_data,
            Intent::sui_transaction(),
            vec![
                GenericSignature::Signature(key_sig),
                GenericSignature::Signature(sponsor_sig),
            ],
        ));

        let tx_res = env.execute_transaction(tx).unwrap();

        let changed_object = tx_res
            .0
            .all_changed_objects()
            .into_iter()
            .find(|o| o.2 == WriteKind::Mutate)
            .unwrap()
            .0;

        let prev_bal = gas_coin::GasCoin::try_from(
            &env.get_object_with_sequence(
                &changed_object.0,
                changed_object.1.one_before().unwrap(),
            )
            .unwrap()
            .unwrap(),
        )
        .unwrap()
        .0
        .balance;

        let current_bal =
            gas_coin::GasCoin::try_from(&env.get_object(&changed_object.0).unwrap().unwrap())
                .unwrap()
                .0
                .balance;

        assert!(
            prev_bal.value() > current_bal.value(),
            "Object with previous sequence number did not contain correct balance"
        );
    }

    #[test]
    fn advance_env_clock() {
        let mut env = Environment::builder().build();

        let duration = std::time::Duration::from_millis(1);
        let effects = env.advance_clock(duration);

        let clock_object_ref = effects.mutated_excluding_gas().pop().unwrap().0;

        let old_timestamp_ms = env
            .get_object_with_sequence(
                &clock_object_ref.0,
                clock_object_ref.1.one_before().unwrap(),
            )
            .unwrap()
            .unwrap()
            .to_rust::<Clock>()
            .unwrap()
            .timestamp_ms;

        let Clock { timestamp_ms, .. } = env
            .get_object(&clock_object_ref.0)
            .unwrap()
            .unwrap()
            .to_rust()
            .unwrap();

        assert_eq!(
            timestamp_ms - old_timestamp_ms,
            duration.as_millis() as u64,
            "Clock did not advance by duration"
        );
    }

    #[test]
    fn create_env_checkpoint() {
        let det_rng = rand::rngs::StdRng::from_seed([0; 32]);

        let mut env = Environment::builder_with_rng(det_rng.clone()).build();

        let digest_a = env.create_checkpoint().digest().clone();

        let mut env = Environment::builder_with_rng(det_rng).build();

        let digest_b = env.create_checkpoint().digest().clone();

        assert_eq!(digest_a, digest_b, "Blank checkpoint digests not equal");
    }

    #[test]
    fn advance_env_epoch() {
        let mut env = Environment::builder().build();

        let epoch_before = env.get_epoch().epoch();

        env.advance_epoch(false);

        let epoch_after = env.get_epoch().epoch();

        assert_eq!(epoch_after - epoch_before, 1, "Epoch did not advance");
    }
}
