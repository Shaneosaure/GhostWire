//! Identité `age` dont la clé privée ne quitte JAMAIS la YubiKey.
//!
//! Implémente le protocole `piv-p256` d'`age-plugin-yubikey` :
//!
//!   stanza body = ChaCha20-Poly1305(
//!       key   = HKDF-SHA256(salt, label, shared),
//!       plain = file_key,
//!       nonce = 0x00 × 12,
//!   )
//!
//!   shared = ECDH(slot.privkey, ephemeral.pubkey)            ← matériel
//!   salt   = SEC-1-C(ephemeral.pubkey) || SEC-1-C(slot.pubkey)
//!            (33 + 33 octets, formats COMPRESSÉS)
//!   label  = "age-encryption.org/v1/piv-p256"
//!
//! L'opération ECDH se fait via `PIV General Authenticate` au smartcard.
//! Le secret partagé (32 octets, coordonnée X uniquement) est la seule
//! valeur sensible qui transite côté hôte ; la clé privée reste dans la
//! puce et n'est jamais lisible.

use std::sync::Mutex;

use anyhow::{anyhow, Context, Result};
use age_core::{
    format::{FileKey, Stanza, FILE_KEY_BYTES},
    primitives::hkdf,
};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305,
};
use p256::{elliptic_curve::sec1::ToEncodedPoint, PublicKey};
use secrecy::{ExposeSecret, SecretString};
use yubikey::{
    piv::{self, AlgorithmId, SlotId},
    YubiKey,
};

/// Tag de stanza utilisé par `age-plugin-yubikey`.
const P256_STANZA_TAG: &str = "piv-p256";

/// Label HKDF — DOIT correspondre exactement à `age-plugin-yubikey`.
/// Suit la convention `age-encryption.org/v1/<tag>` (cf. X25519).
const P256_LABEL: &[u8] = b"piv-p256";

pub struct YubiKeyIdentity {
    /// `YubiKey` n'est pas `Sync` ; protégé par un Mutex pour respecter
    /// la signature `&self` imposée par `age::Identity`.
    yubikey: Mutex<YubiKey>,
    slot: SlotId,
}

impl YubiKeyIdentity {
    /// Ouvre la première YubiKey détectée et déverrouille `slot` avec `pin`.
    /// Le PIN est zeroizé automatiquement à la sortie de scope.
    pub fn open(slot: SlotId, pin: SecretString) -> Result<Self> {
        let mut yk = YubiKey::open().context("aucune YubiKey détectée sur PC/SC")?;

        yk.verify_pin(pin.expose_secret().as_bytes())
            .context("PIN YubiKey invalide ou bloqué")?;

        // Sanity check : la slot doit avoir un certificat (= une clé).
        let _cert = yubikey::certificate::Certificate::read(&mut yk, slot)
            .with_context(|| format!("aucun certificat dans la slot PIV {slot:?}"))?;

        Ok(Self {
            yubikey: Mutex::new(yk),
            slot,
        })
    }
}

impl age::Identity for YubiKeyIdentity {
    fn unwrap_stanza(
        &self,
        stanza: &Stanza,
    ) -> Option<std::result::Result<FileKey, age::DecryptError>> {
        // On ne traite que les stanzas piv-p256 ; pour les autres on rend
        // None pour qu'`age` continue à essayer les autres identités.
        if stanza.tag != P256_STANZA_TAG {
            return None;
        }
        Some(self.unwrap_p256_stanza(stanza))
    }
}

impl YubiKeyIdentity {
    fn unwrap_p256_stanza(
    &self,
    stanza: &Stanza,
) -> std::result::Result<FileKey, age::DecryptError> {
    // Format de la stanza piv-p256 :
    //   args[0] = SHA-256(SEC-1-C(slot_pubkey))[:4]   (recipient tag, b64, 4o)
    //   args[1] = SEC-1-C(ephemeral_pubkey)           (b64, 33o)
    //   body    = ChaCha20-Poly1305 ciphertext        (32o = file_key 16o + tag 16o)

    let ephemeral_b64 = stanza
        .args
        .get(1)
        .ok_or_else(|| dec_err("stanza piv-p256 sans pubkey éphémère"))?;
    let ephemeral_bytes = base64_decode(ephemeral_b64)
        .ok_or_else(|| dec_err("pubkey éphémère mal encodée (base64)"))?;

    let ephemeral_pk = PublicKey::from_sec1_bytes(&ephemeral_bytes)
        .map_err(|_| dec_err("pubkey éphémère P-256 invalide"))?;

    // (1) ECDH matériel — la YubiKey clignote ici si touch_policy != Never.
    //     L'API PIV exige le format NON-compressé (65 octets, préfixe 0x04).
    let ephemeral_uncompressed = ephemeral_pk.to_encoded_point(false);
    let mut yk = self
        .yubikey
        .lock()
        .map_err(|_| dec_err("mutex YubiKey empoisonné"))?;
    let shared = piv::decrypt_data(
        &mut yk,
        ephemeral_uncompressed.as_bytes(),
        AlgorithmId::EccP256,
        self.slot,
    )
    .map_err(|e| dec_err(&format!("ECDH PIV a échoué : {e}")))?;

    // (2) HKDF — salt = compressed_ephemeral (33o) || compressed_slot_pub (33o).
    //     Label = "piv-p256" (PAS "age-encryption.org/v1/piv-p256" malgré X25519).
    //     IKM   = shared (32o = X coordinate de l'ECDH).
    let slot_pk = read_slot_public_key(&mut yk, self.slot)
        .map_err(|e| dec_err(&format!("lecture pubkey slot : {e}")))?;
    let ephemeral_compressed = ephemeral_pk.to_encoded_point(true);
    let slot_compressed = slot_pk.to_encoded_point(true);

    let mut salt = Vec::with_capacity(66);
    salt.extend_from_slice(ephemeral_compressed.as_bytes());
    salt.extend_from_slice(slot_compressed.as_bytes());

    let wrap_key = hkdf(&salt, P256_LABEL, shared.as_slice());

    // (3) AEAD ChaCha20-Poly1305 (nonce = 12×0x00).
    if stanza.body.len() != FILE_KEY_BYTES + 16 {
        return Err(dec_err("longueur body stanza inattendue"));
    }
    let cipher = ChaCha20Poly1305::new((&wrap_key).into());
    let nonce = [0u8; 12];
    let plaintext = cipher
        .decrypt((&nonce).into(), stanza.body.as_slice())
        .map_err(|_| dec_err("file key wrap invalide"))?;

    let mut file_key = [0u8; FILE_KEY_BYTES];
    file_key.copy_from_slice(&plaintext);
    Ok(FileKey::from(file_key))
  }
}

/// Lit le certificat de la slot et en extrait la clé publique P-256.
fn read_slot_public_key(yk: &mut YubiKey, slot: SlotId) -> Result<PublicKey> {
    let cert = yubikey::certificate::Certificate::read(yk, slot)
        .context("lecture du certificat de slot")?;
    // `raw_bytes()` rend les octets bruts du SubjectPublicKey (sans l'octet
    // "unused bits" du BitString DER) — pour une clé EC c'est le SEC-1
    // uncompressed : `0x04 || X || Y` (65 octets).
    let raw = cert.subject_pki().subject_public_key.raw_bytes();
    PublicKey::from_sec1_bytes(raw).map_err(|e| anyhow!("parse pubkey SPKI : {e}"))
}

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
    STANDARD_NO_PAD.decode(s).ok()
}

fn dec_err(msg: &str) -> age::DecryptError {
    tracing::warn!(target: "wgyk_core::crypto", "déchiffrement YubiKey : {msg}");
    age::DecryptError::KeyDecryptionFailed
}