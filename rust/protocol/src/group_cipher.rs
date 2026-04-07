//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::cell::RefCell;

use rand::{CryptoRng, Rng};
use uuid::Uuid;

use crate::protocol::SENDERKEY_MESSAGE_CURRENT_VERSION;
use crate::sender_keys::{SenderKeyState, SenderMessageKey};
use crate::{
    CiphertextMessageType, KeyPair, ProtocolAddress, Result, SenderKeyDistributionMessage,
    SenderKeyMessage, SenderKeyRecord, SenderKeyStore, SignalProtocolError, consts,
};

/// Thread-local that captures the signing key from the most recently processed
/// SenderKeyDistributionMessage. Consumed (taken) by the caller after open_envelope.
/// 32 bytes: Curve25519 public key (no 0x05 prefix).
thread_local! {
    pub static LAST_SKDM_SIGNING_KEY: RefCell<Option<Vec<u8>>> = RefCell::new(None);
}

/// Thread-locals that capture the raw SenderKeyMessage bytes and the
/// SenderMessageKey seed from the most recent group_decrypt() call.
/// Used by the relay to forward cryptographic proof to the smart contract
/// for on-chain signature verification and decryption.
thread_local! {
    /// Raw SenderKeyMessage wire bytes (version + protobuf + 64-byte signature).
    pub static LAST_SKM_BYTES: RefCell<Option<Vec<u8>>> = RefCell::new(None);
    /// SenderMessageKey seed (32 bytes) — input to HKDF("WhisperGroup") → iv + cipher_key.
    pub static LAST_SKM_SEED: RefCell<Option<Vec<u8>>> = RefCell::new(None);
}

pub async fn group_encrypt<R: Rng + CryptoRng>(
    sender_key_store: &mut dyn SenderKeyStore,
    sender: &ProtocolAddress,
    distribution_id: Uuid,
    plaintext: &[u8],
    csprng: &mut R,
) -> Result<SenderKeyMessage> {
    let mut record = sender_key_store
        .load_sender_key(sender, distribution_id)
        .await?
        .ok_or(SignalProtocolError::NoSenderKeyState { distribution_id })?;

    let sender_key_state = record
        .sender_key_state_mut()
        .map_err(|_| SignalProtocolError::InvalidSenderKeySession { distribution_id })?;

    let message_version = sender_key_state
        .message_version()
        .try_into()
        .map_err(|_| SignalProtocolError::InvalidSenderKeySession { distribution_id })?;

    let sender_chain_key = sender_key_state
        .sender_chain_key()
        .ok_or(SignalProtocolError::InvalidSenderKeySession { distribution_id })?;

    let message_keys = sender_chain_key.sender_message_key();

    let ciphertext =
        signal_crypto::aes_256_cbc_encrypt(plaintext, message_keys.cipher_key(), message_keys.iv())
            .map_err(|_| {
                log::error!(
                    "outgoing sender key state corrupt for distribution ID {distribution_id}",
                );
                SignalProtocolError::InvalidSenderKeySession { distribution_id }
            })?;

    let signing_key = sender_key_state
        .signing_key_private()
        .map_err(|_| SignalProtocolError::InvalidSenderKeySession { distribution_id })?;

    let skm = SenderKeyMessage::new(
        message_version,
        distribution_id,
        sender_key_state.chain_id(),
        message_keys.iteration(),
        ciphertext.into_boxed_slice(),
        csprng,
        &signing_key,
    )?;

    sender_key_state.set_sender_chain_key(sender_chain_key.next()?);

    sender_key_store
        .store_sender_key(sender, distribution_id, &record)
        .await?;

    Ok(skm)
}

fn get_sender_key(
    state: &mut SenderKeyState,
    iteration: u32,
    distribution_id: Uuid,
) -> Result<SenderMessageKey> {
    let sender_chain_key = state
        .sender_chain_key()
        .ok_or(SignalProtocolError::InvalidSenderKeySession { distribution_id })?;
    let current_iteration = sender_chain_key.iteration();

    if current_iteration > iteration {
        if let Some(smk) = state.remove_sender_message_key(iteration) {
            return Ok(smk);
        } else {
            log::info!(
                "SenderKey distribution {distribution_id} Duplicate message for iteration: {iteration}"
            );
            return Err(SignalProtocolError::DuplicatedMessage(
                current_iteration,
                iteration,
            ));
        }
    }

    let jump = (iteration - current_iteration) as usize;
    if jump > consts::MAX_FORWARD_JUMPS {
        log::error!(
            "SenderKey distribution {} Exceeded future message limit: {}, current iteration: {})",
            distribution_id,
            consts::MAX_FORWARD_JUMPS,
            current_iteration
        );
        return Err(SignalProtocolError::InvalidMessage(
            CiphertextMessageType::SenderKey,
            "message from too far into the future",
        ));
    }

    let mut sender_chain_key = sender_chain_key;

    while sender_chain_key.iteration() < iteration {
        state.add_sender_message_key(&sender_chain_key.sender_message_key());
        sender_chain_key = sender_chain_key.next()?;
    }

    state.set_sender_chain_key(sender_chain_key.next()?);
    Ok(sender_chain_key.sender_message_key())
}

pub async fn group_decrypt(
    skm_bytes: &[u8],
    sender_key_store: &mut dyn SenderKeyStore,
    sender: &ProtocolAddress,
) -> Result<Vec<u8>> {
    let skm = SenderKeyMessage::try_from(skm_bytes)?;

    let distribution_id = skm.distribution_id();
    let chain_id = skm.chain_id();

    let mut record = sender_key_store
        .load_sender_key(sender, skm.distribution_id())
        .await?
        .ok_or(SignalProtocolError::NoSenderKeyState { distribution_id })?;

    let sender_key_state = match record.sender_key_state_for_chain_id(chain_id) {
        Some(state) => state,
        None => {
            log::error!(
                "SenderKey distribution {} could not find chain ID {} (known chain IDs: {:?})",
                distribution_id,
                chain_id,
                record.chain_ids_for_logging().collect::<Vec<_>>(),
            );
            return Err(SignalProtocolError::NoSenderKeyState { distribution_id });
        }
    };

    let message_version = skm.message_version() as u32;
    if message_version != sender_key_state.message_version() {
        return Err(SignalProtocolError::UnrecognizedMessageVersion(
            message_version,
        ));
    }

    let signing_key = sender_key_state
        .signing_key_public()
        .map_err(|_| SignalProtocolError::InvalidSenderKeySession { distribution_id })?;
    if !skm.verify_signature(&signing_key)? {
        return Err(SignalProtocolError::SignatureValidationFailed);
    }

    let sender_key = get_sender_key(sender_key_state, skm.iteration(), distribution_id)?;

    // Capture raw bytes + seed for on-chain verification
    LAST_SKM_BYTES.with(|cell| {
        *cell.borrow_mut() = Some(skm_bytes.to_vec());
    });
    LAST_SKM_SEED.with(|cell| {
        *cell.borrow_mut() = Some(sender_key.seed().to_vec());
    });

    let plaintext = match signal_crypto::aes_256_cbc_decrypt(
        skm.ciphertext(),
        sender_key.cipher_key(),
        sender_key.iv(),
    ) {
        Ok(plaintext) => plaintext,
        Err(signal_crypto::DecryptionError::BadKeyOrIv) => {
            log::error!(
                "incoming sender key state corrupt for {sender}, distribution ID {distribution_id}, chain ID {chain_id}",
            );
            return Err(SignalProtocolError::InvalidSenderKeySession { distribution_id });
        }
        Err(signal_crypto::DecryptionError::BadCiphertext(msg)) => {
            log::error!("sender key decryption failed: {msg}");
            return Err(SignalProtocolError::InvalidMessage(
                CiphertextMessageType::SenderKey,
                "decryption failed",
            ));
        }
    };

    sender_key_store
        .store_sender_key(sender, distribution_id, &record)
        .await?;

    Ok(plaintext)
}

pub async fn process_sender_key_distribution_message(
    sender: &ProtocolAddress,
    skdm: &SenderKeyDistributionMessage,
    sender_key_store: &mut dyn SenderKeyStore,
) -> Result<()> {
    let distribution_id = skdm.distribution_id()?;
    log::info!(
        "{} Processing SenderKey distribution {} with chain ID {}",
        sender,
        distribution_id,
        skdm.chain_id()?
    );

    let mut sender_key_record = sender_key_store
        .load_sender_key(sender, distribution_id)
        .await?
        .unwrap_or_else(SenderKeyRecord::new_empty);

    let signing_key = *skdm.signing_key()?;

    sender_key_record.add_sender_key_state(
        skdm.message_version(),
        skdm.chain_id()?,
        skdm.iteration()?,
        skdm.chain_key()?,
        signing_key,
        None,
    );
    sender_key_store
        .store_sender_key(sender, distribution_id, &sender_key_record)
        .await?;

    // Capture the signing key for the relay to register on-chain.
    // The key is 33 bytes serialized (0x05 prefix + 32 bytes Curve25519).
    // Strip the prefix for the 32-byte Montgomery u-coordinate.
    let key_bytes = signing_key.serialize();
    let key_no_prefix = if key_bytes.len() == 33 && key_bytes[0] == 0x05 {
        key_bytes[1..].to_vec()
    } else {
        key_bytes.to_vec()
    };
    LAST_SKDM_SIGNING_KEY.with(|cell| {
        *cell.borrow_mut() = Some(key_no_prefix);
    });

    Ok(())
}

pub async fn create_sender_key_distribution_message<R: Rng + CryptoRng>(
    sender: &ProtocolAddress,
    distribution_id: Uuid,
    sender_key_store: &mut dyn SenderKeyStore,
    csprng: &mut R,
) -> Result<SenderKeyDistributionMessage> {
    let sender_key_record = sender_key_store
        .load_sender_key(sender, distribution_id)
        .await?;

    let sender_key_record = match sender_key_record {
        Some(record) => record,
        None => {
            // libsignal-protocol-java uses 31-bit integers for sender key chain IDs
            let chain_id = (csprng.random::<u32>()) >> 1;
            log::info!(
                "Creating SenderKey for distribution {distribution_id} with chain ID {chain_id}"
            );

            let iteration = 0;
            let sender_key: [u8; 32] = csprng.random();
            let signing_key = KeyPair::generate(csprng);
            let mut record = SenderKeyRecord::new_empty();
            record.add_sender_key_state(
                SENDERKEY_MESSAGE_CURRENT_VERSION,
                chain_id,
                iteration,
                &sender_key,
                signing_key.public_key,
                Some(signing_key.private_key),
            );
            sender_key_store
                .store_sender_key(sender, distribution_id, &record)
                .await?;
            record
        }
    };

    let state = sender_key_record
        .sender_key_state()
        .map_err(|_| SignalProtocolError::InvalidSenderKeySession { distribution_id })?;
    let sender_chain_key = state
        .sender_chain_key()
        .ok_or(SignalProtocolError::InvalidSenderKeySession { distribution_id })?;
    let message_version = state
        .message_version()
        .try_into()
        .map_err(|_| SignalProtocolError::InvalidSenderKeySession { distribution_id })?;

    SenderKeyDistributionMessage::new(
        message_version,
        distribution_id,
        state.chain_id(),
        sender_chain_key.iteration(),
        sender_chain_key.seed().to_vec(),
        state
            .signing_key_public()
            .map_err(|_| SignalProtocolError::InvalidSenderKeySession { distribution_id })?,
    )
}
