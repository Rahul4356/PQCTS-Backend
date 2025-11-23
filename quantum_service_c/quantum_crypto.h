#ifndef QUANTUM_CRYPTO_H
#define QUANTUM_CRYPTO_H

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>

// Constants for cryptographic parameters
#define ML_KEM_768_PUBLIC_KEY_SIZE 1184
#define ML_KEM_768_PRIVATE_KEY_SIZE 2400
#define ML_KEM_768_CIPHERTEXT_SIZE 1088
#define ML_KEM_768_SHARED_SECRET_SIZE 32

#define FALCON_512_PUBLIC_KEY_SIZE 897
#define FALCON_512_PRIVATE_KEY_SIZE 1281
#define FALCON_512_SIGNATURE_MIN_SIZE 600
#define FALCON_512_SIGNATURE_MAX_SIZE 800

#define ECDSA_P256_PUBLIC_KEY_SIZE_MIN 88
#define ECDSA_P256_PUBLIC_KEY_SIZE_MAX 120
#define ECDSA_P256_SIGNATURE_SIZE_MIN 64
#define ECDSA_P256_SIGNATURE_SIZE_MAX 72

#define AES_256_KEY_SIZE 32
#define AES_GCM_IV_SIZE 12
#define AES_GCM_TAG_SIZE 16

// Session key storage structure
typedef struct {
    char user_id[101];
    uint8_t *ml_kem_public;
    uint8_t *ml_kem_private;
    size_t ml_kem_public_size;
    size_t ml_kem_private_size;
    uint8_t *falcon_public;
    uint8_t *falcon_private;
    size_t falcon_public_size;
    size_t falcon_private_size;
    uint8_t *ecdsa_public;
    uint8_t *ecdsa_private;
    size_t ecdsa_public_size;
    size_t ecdsa_private_size;
    time_t created_at;
    char metadata[1024];
} SessionKeys;

// Function declarations for quantum operations
int init_quantum_crypto(void);
void cleanup_quantum_crypto(void);

// Key generation
int generate_ml_kem_keypair(uint8_t **public_key, size_t *public_key_len,
                            uint8_t **private_key, size_t *private_key_len);
int generate_falcon_keypair(uint8_t **public_key, size_t *public_key_len,
                           uint8_t **private_key, size_t *private_key_len);
int generate_ecdsa_keypair(uint8_t **public_key, size_t *public_key_len,
                          uint8_t **private_key, size_t *private_key_len);

// ML-KEM operations
int ml_kem_encapsulate(const uint8_t *public_key, size_t public_key_len,
                       uint8_t **ciphertext, size_t *ciphertext_len,
                       uint8_t **shared_secret, size_t *shared_secret_len);
int ml_kem_decapsulate(const uint8_t *ciphertext, size_t ciphertext_len,
                       const uint8_t *private_key, size_t private_key_len,
                       uint8_t **shared_secret, size_t *shared_secret_len);

// Falcon signature operations
int falcon_sign(const uint8_t *message, size_t message_len,
                const uint8_t *private_key, size_t private_key_len,
                uint8_t **signature, size_t *signature_len);
int falcon_verify(const uint8_t *message, size_t message_len,
                  const uint8_t *signature, size_t signature_len,
                  const uint8_t *public_key, size_t public_key_len);

// ECDSA operations
int ecdsa_sign(const uint8_t *message, size_t message_len,
               const uint8_t *private_key, size_t private_key_len,
               uint8_t **signature, size_t *signature_len);
int ecdsa_verify(const uint8_t *message, size_t message_len,
                 const uint8_t *signature, size_t signature_len,
                 const uint8_t *public_key, size_t public_key_len);

// AES-GCM operations
int aes_gcm_encrypt(const uint8_t *plaintext, size_t plaintext_len,
                   const uint8_t *key, size_t key_len,
                   const uint8_t *aad, size_t aad_len,
                   uint8_t **ciphertext, size_t *ciphertext_len,
                   uint8_t **nonce, uint8_t **tag);

int aes_gcm_decrypt(const uint8_t *ciphertext, size_t ciphertext_len,
                   const uint8_t *key, size_t key_len,
                   const uint8_t *nonce, const uint8_t *tag,
                   const uint8_t *aad, size_t aad_len,
                   uint8_t **plaintext, size_t *plaintext_len);

// Session management
SessionKeys* create_session(const char *user_id);
SessionKeys* get_session(const char *user_id);
void delete_session(const char *user_id);
void cleanup_all_sessions(void);

// Utility functions
char* base64_encode(const uint8_t *data, size_t len);
uint8_t* base64_decode(const char *str, size_t *out_len);
char* bytes_to_hex(const uint8_t *data, size_t len);

#endif // QUANTUM_CRYPTO_H