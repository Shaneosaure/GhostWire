//! Pipeline complet : `.conf.age` sur disque  ➜  `SecretString` en RAM.
//!
//! Aucune écriture disque, aucun appel à un binaire externe. La seule
//! interaction matérielle est l'ECDH avec la YubiKey via PC/SC.

use std::io::Read;
use std::path::Path;

use age::Decryptor;
use anyhow::{anyhow, Context, Result};
use secrecy::SecretString;
use yubikey::piv::SlotId;

use crate::crypto::age_yubikey::YubiKeyIdentity;

/// Taille maximale acceptée pour un fichier `.conf` WireGuard une fois
/// déchiffré. 64 Kio est largement supérieur au plus gros conf imaginable
/// (un AllowedIPs très long reste sous le Kio). Cette borne protège d'un
/// fichier malicieux qui essaierait de saturer la RAM.
const MAX_PLAINTEXT_BYTES: u64 = 64 * 1024;

/// Lit un fichier `age` chiffré, demande à la YubiKey de le déchiffrer,
/// et renvoie la configuration WireGuard en clair encapsulée dans un
/// `SecretString` (zeroizé automatiquement à la sortie de scope).
///
/// # Étapes
/// 1. Lecture binaire du `.conf.age` en RAM.
/// 2. Ouverture + verify_pin de la YubiKey.
/// 3. Construction d'un `age::Decryptor::Recipients`.
/// 4. Streaming du déchiffrement en RAM, avec borne anti-OOM.
/// 5. Validation UTF-8 et encapsulation `SecretString`.
pub fn decrypt_config(
    encrypted_path: impl AsRef<Path>,
    pin: SecretString,
    slot: SlotId,
) -> Result<SecretString> {
    let path = encrypted_path.as_ref();
    tracing::info!(?path, "déchiffrement YubiKey en RAM");

    // (1) Le seul I/O disque autorisé : lire le ciphertext.
    let ciphertext = std::fs::read(path)
        .with_context(|| format!("impossible de lire {}", path.display()))?;

    // (2) Identité matérielle. Le PIN sera consommé puis zeroizé.
    let identity = YubiKeyIdentity::open(slot, pin)
        .context("ouverture de l'identité YubiKey")?;

    // (3) Décryptor `age`. On rejette explicitement les fichiers chiffrés
    //     par passphrase : pour ce client, seuls les destinataires PIV ont
    //     du sens, sinon la YubiKey ne sert à rien.
    let decryptor = Decryptor::new(&ciphertext[..])
        .context("le fichier n'est pas un flux age valide")?;
    if decryptor.is_scrypt() {
        return Err(anyhow!(
            "fichier chiffré par passphrase : non supporté par ce client"
        ));
    }

    // (4) Streaming + borne. On itère un seul `dyn Identity` : la YubiKey.
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .context("aucune stanza n'a pu être déverrouillée par la YubiKey")?;

    let mut plaintext = Vec::with_capacity(4096);
    reader
        .by_ref()
        .take(MAX_PLAINTEXT_BYTES)
        .read_to_end(&mut plaintext)
        .context("erreur de streaming pendant le déchiffrement")?;

    // Détecte le cas pathologique d'un fichier > MAX : si on a lu pile la
    // borne, il reste peut-être des octets non lus → on refuse.
    if plaintext.len() as u64 == MAX_PLAINTEXT_BYTES {
        let mut probe = [0u8; 1];
        if reader.read(&mut probe).unwrap_or(0) > 0 {
            return Err(anyhow!("config déchiffrée > {MAX_PLAINTEXT_BYTES} o : refus"));
        }
    }

    // (5) WireGuard impose UTF-8 (ASCII en pratique).
    let s = String::from_utf8(plaintext)
        .map_err(|e| anyhow!("config déchiffrée non-UTF-8 : {e}"))?;

    tracing::info!(bytes = s.len(), "config WireGuard déchiffrée en RAM");
    Ok(SecretString::new(s.into_boxed_str()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test d'intégration nécessitant une YubiKey physique. On le marque
    /// `ignore` pour qu'il ne casse pas la CI.
    #[test]
    #[ignore = "nécessite une YubiKey insérée + slot PIV 9c configurée"]
    fn poc_decrypt_real_yubikey() {
        let pin = SecretString::new("123456".to_string().into_boxed_str()); // PIN par défaut
        let cfg = decrypt_config(
            "tests/fixtures/client.conf.age",
            pin,
            yubikey::piv::SlotId::Authentication, // slot 9a
        )
        .expect("déchiffrement OK");

        // Validation très basique — on ne logge JAMAIS le contenu.
        let plaintext = secrecy::ExposeSecret::expose_secret(&cfg);
        assert!(plaintext.contains("[Interface]"));
        assert!(plaintext.contains("PrivateKey"));
    }
}