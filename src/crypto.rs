// AES-GCM crypto + lightweight KDF + perf counters
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Error as AesError};
use sha2::{Digest, Sha256};

// 96-bit nonce for GCM
type Nonce = GenericArray<u8, aes_gcm::aead::generic_array::typenum::U12>;

/// SHA256-based slow KDF params
/// Not PBKDF2/Argon2 but better than single hash
const KDF_SALT: &[u8] = b"fuscen-v13-static-salt";
const KDF_ITERATIONS: u32 = 100_000;

/// Tunnel crypto context with counters
#[derive(Clone)]
pub struct TunnelCrypto {
    // One of these is set
    cipher128: Option<Aes128Gcm>,
    cipher256: Option<Aes256Gcm>,

    // Telemetry only
    encrypt_ops: Arc<AtomicU64>,
    decrypt_ops: Arc<AtomicU64>,
    processed_bytes: Arc<AtomicU64>,

    // Mode flag
    use_aes256: bool,
}

impl TunnelCrypto {
    /// AES-128-GCM from password
    pub fn new(password: &str) -> Self {
        // Derive fixed-size key
        let derived = derive_key_from_password(password, 16);
        let key: &[u8] = &derived;

        // Optional HW notice
        #[cfg(target_arch = "x86_64")]
        Self::check_aesni_support();

        Self {
            cipher128: Some(
                Aes128Gcm::new_from_slice(key)
                    .expect("[FATAL] Key must be 16 bytes for AES-128-GCM"),
            ),
            cipher256: None,
            encrypt_ops: Arc::new(AtomicU64::new(0)),
            decrypt_ops: Arc::new(AtomicU64::new(0)),
            processed_bytes: Arc::new(AtomicU64::new(0)),
            use_aes256: false,
        }
    }

    /// AES-256-GCM from password
    pub fn new_aes256(password: &str) -> Self {
        // Derive fixed-size key
        let derived = derive_key_from_password(password, 32);
        let key: &[u8] = &derived;

        // Optional HW notice
        #[cfg(target_arch = "x86_64")]
        Self::check_aesni_support();

        Self {
            cipher128: None,
            cipher256: Some(
                Aes256Gcm::new_from_slice(key)
                    .expect("[FATAL] Key must be 32 bytes for AES-256-GCM"),
            ),
            encrypt_ops: Arc::new(AtomicU64::new(0)),
            decrypt_ops: Arc::new(AtomicU64::new(0)),
            processed_bytes: Arc::new(AtomicU64::new(0)),
            use_aes256: true,
        }
    }

    /// Best-effort AES-NI check
    #[cfg(target_arch = "x86_64")]
    fn check_aesni_support() {
        use std::arch::x86_64::__cpuid;

        unsafe {
            let cpuid = __cpuid(1);
            let has_aesni = (cpuid.ecx & (1 << 25)) != 0;

            if has_aesni {
                println!("[✓] AES-NI hardware acceleration enabled");
            } else {
                println!("[⚠] AES-NI not detected - using software implementation");
            }
        }
    }

    /// Non-x86 fallback
    #[cfg(not(target_arch = "x86_64"))]
    fn check_aesni_support() {
        println!("[ℹ] AES acceleration check available only on x86_64");
    }

    /// Nonce from monotonically increasing counter
    /// Caller must ensure (key,counter) uniqueness per direction
    fn generate_nonce(counter: u64) -> Nonce {
        let mut nonce = [0u8; 12];
        // 32-bit prefix reserved, 64-bit counter in BE
        nonce[4..].copy_from_slice(&counter.to_be_bytes());
        GenericArray::from_slice(&nonce).clone()
    }

    /// Encrypt into provided buffer
    pub fn encrypt(&self, counter: u64, plaintext: &[u8], buffer: &mut Vec<u8>) -> usize {
        let nonce = Self::generate_nonce(counter);

        // Copy then encrypt in place
        buffer.clear();
        buffer.extend_from_slice(plaintext);
        // Space for GCM tag
        buffer.reserve(16);

        let res = if self.use_aes256 {
            self.cipher256
                .as_ref()
                .expect("[FATAL] AES-256 cipher not initialized")
                .encrypt_in_place(&nonce, &[], buffer)
        } else {
            self.cipher128
                .as_ref()
                .expect("[FATAL] AES-128 cipher not initialized")
                .encrypt_in_place(&nonce, &[], buffer)
        };

        // Keep behavior as-is
        if res.is_err() {
            panic!("[ERROR] Encryption failed");
        }

        // Perf counters
        self.encrypt_ops.fetch_add(1, Ordering::Relaxed);
        self.processed_bytes
            .fetch_add(plaintext.len() as u64, Ordering::Relaxed);

        buffer.len()
    }

    /// Decrypt into provided buffer
    pub fn decrypt(&self, counter: u64, ciphertext: &[u8], buffer: &mut Vec<u8>) -> Option<usize> {
        // Must contain tag
        if ciphertext.len() < 16 {
            return None;
        }

        let nonce = Self::generate_nonce(counter);

        // Copy then decrypt in place
        buffer.clear();
        buffer.extend_from_slice(ciphertext);

        let result = if self.use_aes256 {
            self.cipher256
                .as_ref()
                .expect("[FATAL] AES-256 cipher not initialized")
                .decrypt_in_place(&nonce, &[], buffer)
        } else {
            self.cipher128
                .as_ref()
                .expect("[FATAL] AES-128 cipher not initialized")
                .decrypt_in_place(&nonce, &[], buffer)
        };

        match result {
            Ok(_) => {
                // buffer now holds plaintext
                let plaintext_len = buffer.len();
                self.decrypt_ops.fetch_add(1, Ordering::Relaxed);
                self.processed_bytes
                    .fetch_add(plaintext_len as u64, Ordering::Relaxed);
                Some(plaintext_len)
            }
            Err(_) => None,
        }
    }

    /// Encrypt in place for zero-copy paths
    pub fn encrypt_inplace(&self, counter: u64, data: &mut Vec<u8>) -> Result<usize, AesError> {
        let nonce = Self::generate_nonce(counter);

        let original_len = data.len();
        // Space for tag
        data.reserve(16);

        if self.use_aes256 {
            self.cipher256
                .as_ref()
                .expect("[FATAL] AES-256 cipher not initialized")
                .encrypt_in_place(&nonce, &[], data)?;
        } else {
            self.cipher128
                .as_ref()
                .expect("[FATAL] AES-128 cipher not initialized")
                .encrypt_in_place(&nonce, &[], data)?;
        }

        // Perf counters
        self.encrypt_ops.fetch_add(1, Ordering::Relaxed);
        self.processed_bytes
            .fetch_add(original_len as u64, Ordering::Relaxed);

        Ok(data.len())
    }

    /// Reset perf counters only
    pub fn reset_counters(&self) {
        self.encrypt_ops.store(0, Ordering::Release);
        self.decrypt_ops.store(0, Ordering::Release);
        self.processed_bytes.store(0, Ordering::Release);
    }

    /// (encrypt_ops, decrypt_ops, processed_bytes)
    pub fn get_performance_stats(&self) -> (u64, u64, u64) {
        let sent = self.encrypt_ops.load(Ordering::Acquire);
        let received = self.decrypt_ops.load(Ordering::Acquire);
        let processed = self.processed_bytes.load(Ordering::Acquire);

        (sent, received, processed)
    }

    /// AES-256 mode flag
    pub fn is_aes256(&self) -> bool {
        self.use_aes256
    }
}

/// Simple iterative SHA256 KDF
fn derive_key_from_password(password: &str, key_len: usize) -> Vec<u8> {
    let mut key = Vec::with_capacity(key_len);
    let mut block_index: u32 = 0;

    // Expand using chained blocks
    while key.len() < key_len {
        block_index = block_index.wrapping_add(1);

        // salt || password || block_index
        let mut hasher = Sha256::new();
        hasher.update(KDF_SALT);
        hasher.update(password.as_bytes());
        hasher.update(&block_index.to_be_bytes());
        let mut digest = hasher.finalize_reset();

        // Slowdown loop
        for _ in 0..KDF_ITERATIONS {
            hasher.update(&digest);
            digest = hasher.finalize_reset();
        }

        // Append as needed
        let need = key_len - key.len();
        if need >= digest.len() {
            key.extend_from_slice(&digest);
        } else {
            key.extend_from_slice(&digest[..need]);
        }
    }

    key
}