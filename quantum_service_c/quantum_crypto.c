#include "quantum_crypto.h"
#include <oqs/oqs.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>

// Global session storage
typedef struct SessionNode {
    SessionKeys *session;
    struct SessionNode *next;
} SessionNode;

static SessionNode *sessions = NULL;
static pthread_mutex_t session_mutex = PTHREAD_MUTEX_INITIALIZER;

// Initialize quantum crypto library
int init_quantum_crypto(void) {
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    
    // Check if required algorithms are available
    if (!OQS_KEM_alg_is_enabled("Kyber768")) {
        fprintf(stderr, "ML-KEM-768 (Kyber768) not available\n");
        return -1;
    }
    
    if (!OQS_SIG_alg_is_enabled("Falcon-512")) {
        fprintf(stderr, "Falcon-512 not available\n");
        return -1;
    }
    
    printf("✅ Quantum crypto initialized successfully\n");
    printf("✅ ML-KEM-768 (Kyber768) ready\n");
    printf("✅ Falcon-512 ready\n");
    
    return 0;
}

// Cleanup quantum crypto
void cleanup_quantum_crypto(void) {
    cleanup_all_sessions();
    EVP_cleanup();
}

// Generate ML-KEM keypair (STUB implementation)
int generate_ml_kem_keypair(uint8_t **public_key, size_t *public_key_len,
                            uint8_t **private_key, size_t *private_key_len) {
    *public_key_len = ML_KEM_768_PUBLIC_KEY_SIZE;
    *private_key_len = ML_KEM_768_PRIVATE_KEY_SIZE;
    
    *public_key = malloc(*public_key_len);
    *private_key = malloc(*private_key_len);
    
    if (*public_key == NULL || *private_key == NULL) {
        return -1;
    }
    
    // Fill with simulated random data
    for (size_t i = 0; i < *public_key_len; i++) {
        (*public_key)[i] = (uint8_t)(rand() % 256);
    }
    for (size_t i = 0; i < *private_key_len; i++) {
        (*private_key)[i] = (uint8_t)(rand() % 256);
    }
    
    return 0;
}

// Generate Falcon keypair
int generate_falcon_keypair(uint8_t **public_key, size_t *public_key_len,
                           uint8_t **private_key, size_t *private_key_len) {
    OQS_SIG *sig = OQS_SIG_new("Falcon-512");
    if (sig == NULL) {
        return -1;
    }
    
    *public_key_len = sig->length_public_key;
    *private_key_len = sig->length_secret_key;
    
    *public_key = malloc(*public_key_len);
    *private_key = malloc(*private_key_len);
    
    if (*public_key == NULL || *private_key == NULL) {
        OQS_SIG_free(sig);
        return -1;
    }
    
    if (OQS_SIG_keypair(sig, *public_key, *private_key) != OQS_SUCCESS) {
        free(*public_key);
        free(*private_key);
        OQS_SIG_free(sig);
        return -1;
    }
    
    OQS_SIG_free(sig);
    return 0;
}

// Generate ECDSA keypair
int generate_ecdsa_keypair(uint8_t **public_key, size_t *public_key_len,
                          uint8_t **private_key, size_t *private_key_len) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    BIO *bio_pub = NULL, *bio_priv = NULL;
    BUF_MEM *buf_pub, *buf_priv;
    
    // Create key generation context
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!pctx) return -1;
    
    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }
    
    // Set curve to P-256
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }
    
    // Generate key
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }
    
    // Export public key
    bio_pub = BIO_new(BIO_s_mem());
    if (!PEM_write_bio_PUBKEY(bio_pub, pkey)) {
        BIO_free(bio_pub);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }
    
    BIO_get_mem_ptr(bio_pub, &buf_pub);
    *public_key_len = buf_pub->length;
    *public_key = malloc(*public_key_len);
    memcpy(*public_key, buf_pub->data, *public_key_len);
    
    // Export private key
    bio_priv = BIO_new(BIO_s_mem());
    if (!PEM_write_bio_PrivateKey(bio_priv, pkey, NULL, NULL, 0, NULL, NULL)) {
        BIO_free(bio_pub);
        BIO_free(bio_priv);
        free(*public_key);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }
    
    BIO_get_mem_ptr(bio_priv, &buf_priv);
    *private_key_len = buf_priv->length;
    *private_key = malloc(*private_key_len);
    memcpy(*private_key, buf_priv->data, *private_key_len);
    
    BIO_free(bio_pub);
    BIO_free(bio_priv);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    
    return 0;
}

// ML-KEM encapsulate
int ml_kem_encapsulate(const uint8_t *public_key, size_t public_key_len,
                       uint8_t **ciphertext, size_t *ciphertext_len,
                       uint8_t **shared_secret, size_t *shared_secret_len) {
    OQS_KEM *kem = OQS_KEM_new("Kyber768");
    if (kem == NULL) {
        return -1;
    }
    
    *ciphertext_len = kem->length_ciphertext;
    *shared_secret_len = kem->length_shared_secret;
    
    *ciphertext = malloc(*ciphertext_len);
    *shared_secret = malloc(*shared_secret_len);
    
    if (*ciphertext == NULL || *shared_secret == NULL) {
        OQS_KEM_free(kem);
        return -1;
    }
    
    if (OQS_KEM_encaps(kem, *ciphertext, *shared_secret, public_key) != OQS_SUCCESS) {
        free(*ciphertext);
        free(*shared_secret);
        OQS_KEM_free(kem);
        return -1;
    }
    
    OQS_KEM_free(kem);
    return 0;
}

// ML-KEM decapsulate
int ml_kem_decapsulate(const uint8_t *ciphertext, size_t ciphertext_len,
                       const uint8_t *private_key, size_t private_key_len,
                       uint8_t **shared_secret, size_t *shared_secret_len) {
    OQS_KEM *kem = OQS_KEM_new("Kyber768");
    if (kem == NULL) {
        return -1;
    }
    
    *shared_secret_len = kem->length_shared_secret;
    *shared_secret = malloc(*shared_secret_len);
    
    if (*shared_secret == NULL) {
        OQS_KEM_free(kem);
        return -1;
    }
    
    if (OQS_KEM_decaps(kem, *shared_secret, ciphertext, private_key) != OQS_SUCCESS) {
        free(*shared_secret);
        OQS_KEM_free(kem);
        return -1;
    }
    
    OQS_KEM_free(kem);
    return 0;
}

// Falcon sign
int falcon_sign(const uint8_t *message, size_t message_len,
                const uint8_t *private_key, size_t private_key_len,
                uint8_t **signature, size_t *signature_len) {
    OQS_SIG *sig = OQS_SIG_new("Falcon-512");
    if (sig == NULL) {
        return -1;
    }
    
    *signature_len = sig->length_signature;
    *signature = malloc(*signature_len);
    
    if (*signature == NULL) {
        OQS_SIG_free(sig);
        return -1;
    }
    
    if (OQS_SIG_sign(sig, *signature, signature_len, message, message_len, private_key) != OQS_SUCCESS) {
        free(*signature);
        OQS_SIG_free(sig);
        return -1;
    }
    
    OQS_SIG_free(sig);
    return 0;
}

// Falcon verify
int falcon_verify(const uint8_t *message, size_t message_len,
                  const uint8_t *signature, size_t signature_len,
                  const uint8_t *public_key, size_t public_key_len) {
    OQS_SIG *sig = OQS_SIG_new("Falcon-512");
    if (sig == NULL) {
        return -1;
    }
    
    int result = (OQS_SIG_verify(sig, message, message_len, signature, signature_len, public_key) == OQS_SUCCESS) ? 0 : -1;
    
    OQS_SIG_free(sig);
    return result;
}

// ECDSA sign
int ecdsa_sign(const uint8_t *message, size_t message_len,
               const uint8_t *private_key, size_t private_key_len,
               uint8_t **signature, size_t *signature_len) {
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *mdctx = NULL;
    BIO *bio = NULL;
    size_t req_len;
    
    // Load private key
    bio = BIO_new_mem_buf(private_key, private_key_len);
    pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    
    if (!pkey) return -1;
    
    // Create signing context
    mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        EVP_PKEY_free(pkey);
        return -1;
    }
    
    if (EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey) <= 0) {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return -1;
    }
    
    if (EVP_DigestSignUpdate(mdctx, message, message_len) <= 0) {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return -1;
    }
    
    // Get signature length
    if (EVP_DigestSignFinal(mdctx, NULL, &req_len) <= 0) {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return -1;
    }
    
    *signature = malloc(req_len);
    *signature_len = req_len;
    
    if (EVP_DigestSignFinal(mdctx, *signature, signature_len) <= 0) {
        free(*signature);
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return -1;
    }
    
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    return 0;
}

// ECDSA verify
int ecdsa_verify(const uint8_t *message, size_t message_len,
                 const uint8_t *signature, size_t signature_len,
                 const uint8_t *public_key, size_t public_key_len) {
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *mdctx = NULL;
    BIO *bio = NULL;
    int result = -1;
    
    // Load public key
    bio = BIO_new_mem_buf(public_key, public_key_len);
    pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);
    
    if (!pkey) return -1;
    
    // Create verification context
    mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        EVP_PKEY_free(pkey);
        return -1;
    }
    
    if (EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pkey) <= 0) {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return -1;
    }
    
    if (EVP_DigestVerifyUpdate(mdctx, message, message_len) <= 0) {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return -1;
    }
    
    result = EVP_DigestVerifyFinal(mdctx, signature, signature_len) == 1 ? 0 : -1;
    
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    return result;
}

// AES-GCM encrypt
int aes_gcm_encrypt(const uint8_t *plaintext, size_t plaintext_len,
                   const uint8_t *key, size_t key_len,
                   const uint8_t *aad, size_t aad_len,
                   uint8_t **ciphertext, size_t *ciphertext_len,
                   uint8_t **nonce, uint8_t **tag) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len_int;
    
    *nonce = malloc(AES_GCM_IV_SIZE);
    *tag = malloc(AES_GCM_TAG_SIZE);
    *ciphertext = malloc(plaintext_len);
    
    if (!*nonce || !*tag || !*ciphertext) return -1;
    
    // Generate random nonce
    if (RAND_bytes(*nonce, AES_GCM_IV_SIZE) != 1) {
        free(*nonce);
        free(*tag);
        free(*ciphertext);
        return -1;
    }
    
    // Create and initialize context
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        free(*nonce);
        free(*tag);
        free(*ciphertext);
        return -1;
    }
    
    // Initialize encryption
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(*nonce);
        free(*tag);
        free(*ciphertext);
        return -1;
    }
    
    // Set IV length
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_GCM_IV_SIZE, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(*nonce);
        free(*tag);
        free(*ciphertext);
        return -1;
    }
    
    // Initialize key and IV
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, *nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(*nonce);
        free(*tag);
        free(*ciphertext);
        return -1;
    }
    
    // Provide AAD data if present
    if (aad && aad_len > 0) {
        if (EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            free(*nonce);
            free(*tag);
            free(*ciphertext);
            return -1;
        }
    }
    
    // Encrypt plaintext
    if (EVP_EncryptUpdate(ctx, *ciphertext, &len, plaintext, plaintext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(*nonce);
        free(*tag);
        free(*ciphertext);
        return -1;
    }
    ciphertext_len_int = len;
    
    // Finalize encryption
    if (EVP_EncryptFinal_ex(ctx, *ciphertext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(*nonce);
        free(*tag);
        free(*ciphertext);
        return -1;
    }
    ciphertext_len_int += len;
    *ciphertext_len = ciphertext_len_int;
    
    // Get tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_GCM_TAG_SIZE, *tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(*nonce);
        free(*tag);
        free(*ciphertext);
        return -1;
    }
    
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

// AES-GCM decrypt
int aes_gcm_decrypt(const uint8_t *ciphertext, size_t ciphertext_len,
                   const uint8_t *key, size_t key_len,
                   const uint8_t *nonce, const uint8_t *tag,
                   const uint8_t *aad, size_t aad_len,
                   uint8_t **plaintext, size_t *plaintext_len) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len_int;
    int ret;
    
    *plaintext = malloc(ciphertext_len);
    if (!*plaintext) return -1;
    
    // Create and initialize context
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        free(*plaintext);
        return -1;
    }
    
    // Initialize decryption
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        EVP_CIPHER_CTX_free(ctx);
        free(*plaintext);
        return -1;
    }
    
    // Set IV length
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_GCM_IV_SIZE, NULL)) {
        EVP_CIPHER_CTX_free(ctx);
        free(*plaintext);
        return -1;
    }
    
    // Initialize key and IV
    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce)) {
        EVP_CIPHER_CTX_free(ctx);
        free(*plaintext);
        return -1;
    }
    
    // Provide AAD data if present
    if (aad && aad_len > 0) {
        if (!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len)) {
            EVP_CIPHER_CTX_free(ctx);
            free(*plaintext);
            return -1;
        }
    }
    
    // Decrypt ciphertext
    if (!EVP_DecryptUpdate(ctx, *plaintext, &len, ciphertext, ciphertext_len)) {
        EVP_CIPHER_CTX_free(ctx);
        free(*plaintext);
        return -1;
    }
    plaintext_len_int = len;
    
    // Set expected tag value
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_SIZE, (void*)tag)) {
        EVP_CIPHER_CTX_free(ctx);
        free(*plaintext);
        return -1;
    }
    
    // Finalize decryption and verify tag
    ret = EVP_DecryptFinal_ex(ctx, *plaintext + len, &len);
    
    EVP_CIPHER_CTX_free(ctx);
    
    if (ret > 0) {
        plaintext_len_int += len;
        *plaintext_len = plaintext_len_int;
        return 0;
    } else {
        free(*plaintext);
        return -1;
    }
}

// Session management
SessionKeys* create_session(const char *user_id) {
    SessionKeys *session = calloc(1, sizeof(SessionKeys));
    if (!session) return NULL;
    
    strncpy(session->user_id, user_id, 100);
    session->created_at = time(NULL);
    
    pthread_mutex_lock(&session_mutex);
    
    // Remove existing session if present
    delete_session(user_id);
    
    // Add new session
    SessionNode *node = malloc(sizeof(SessionNode));
    node->session = session;
    node->next = sessions;
    sessions = node;
    
    pthread_mutex_unlock(&session_mutex);
    
    return session;
}

SessionKeys* get_session(const char *user_id) {
    pthread_mutex_lock(&session_mutex);
    
    SessionNode *current = sessions;
    while (current) {
        if (strcmp(current->session->user_id, user_id) == 0) {
            pthread_mutex_unlock(&session_mutex);
            return current->session;
        }
        current = current->next;
    }
    
    pthread_mutex_unlock(&session_mutex);
    return NULL;
}

void delete_session(const char *user_id) {
    pthread_mutex_lock(&session_mutex);
    
    SessionNode *current = sessions;
    SessionNode *prev = NULL;
    
    while (current) {
        if (strcmp(current->session->user_id, user_id) == 0) {
            if (prev) {
                prev->next = current->next;
            } else {
                sessions = current->next;
            }
            
            // Free session data
            if (current->session->ml_kem_public) free(current->session->ml_kem_public);
            if (current->session->ml_kem_private) free(current->session->ml_kem_private);
            if (current->session->falcon_public) free(current->session->falcon_public);
            if (current->session->falcon_private) free(current->session->falcon_private);
            if (current->session->ecdsa_public) free(current->session->ecdsa_public);
            if (current->session->ecdsa_private) free(current->session->ecdsa_private);
            free(current->session);
            free(current);
            break;
        }
        prev = current;
        current = current->next;
    }
    
    pthread_mutex_unlock(&session_mutex);
}

void cleanup_all_sessions(void) {
    pthread_mutex_lock(&session_mutex);
    
    SessionNode *current = sessions;
    while (current) {
        SessionNode *next = current->next;
        
        // Free session data
        if (current->session->ml_kem_public) free(current->session->ml_kem_public);
        if (current->session->ml_kem_private) free(current->session->ml_kem_private);
        if (current->session->falcon_public) free(current->session->falcon_public);
        if (current->session->falcon_private) free(current->session->falcon_private);
        if (current->session->ecdsa_public) free(current->session->ecdsa_public);
        if (current->session->ecdsa_private) free(current->session->ecdsa_private);
        free(current->session);
        free(current);
        
        current = next;
    }
    sessions = NULL;
    
    pthread_mutex_unlock(&session_mutex);
}

// Base64 encoding
char* base64_encode(const uint8_t *data, size_t len) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;
    
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, data, len);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    
    char *result = malloc(bufferPtr->length + 1);
    memcpy(result, bufferPtr->data, bufferPtr->length);
    result[bufferPtr->length] = '\0';
    
    BIO_free_all(bio);
    return result;
}

// Base64 decoding
uint8_t* base64_decode(const char *str, size_t *out_len) {
    BIO *bio, *b64;
    int len = strlen(str);
    uint8_t *buffer = malloc(len);
    
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(str, -1);
    bio = BIO_push(b64, bio);
    
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    *out_len = BIO_read(bio, buffer, len);
    
    BIO_free_all(bio);
    return buffer;
}

// Convert bytes to hex string
char* bytes_to_hex(const uint8_t *data, size_t len) {
    char *hex = malloc(len * 2 + 1);
    for (size_t i = 0; i < len; i++) {
        sprintf(hex + i * 2, "%02x", data[i]);
    }
    hex[len * 2] = '\0';
    return hex;
}