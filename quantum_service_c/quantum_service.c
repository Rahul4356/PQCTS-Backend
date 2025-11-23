#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>
#include <ctype.h>
#include "quantum_crypto.h"
#include "json_utils.h"

#define PORT 3001
#define BUFFER_SIZE 65536
#define MAX_HEADERS 100
#define MAX_PATH 256
#define MAX_BODY 1048576  // 1MB max body size

static volatile int running = 1;
static time_t start_time;

// HTTP request structure
typedef struct {
    char method[16];
    char path[MAX_PATH];
    char version[16];
    char headers[MAX_HEADERS][512];
    int header_count;
    char *body;
    size_t body_len;
    char content_type[128];
} HttpRequest;

// HTTP response structure
typedef struct {
    int status_code;
    char status_text[64];
    char content_type[128];
    char *body;
    size_t body_len;
} HttpResponse;

// Signal handler for graceful shutdown
void signal_handler(int sig) {
    if (sig == SIGINT || sig == SIGTERM) {
        printf("\n✅ Shutting down gracefully...\n");
        running = 0;
    }
}

// Parse HTTP request
int parse_http_request(const char *raw_request, HttpRequest *request) {
    memset(request, 0, sizeof(HttpRequest));
    
    // Parse request line
    const char *line_end = strstr(raw_request, "\r\n");
    if (!line_end) return -1;
    
    sscanf(raw_request, "%15s %255s %15s", request->method, request->path, request->version);
    
    // Parse headers
    const char *header_start = line_end + 2;
    request->header_count = 0;
    
    while (header_start && *header_start != '\r') {
        line_end = strstr(header_start, "\r\n");
        if (!line_end) break;
        
        size_t header_len = line_end - header_start;
        if (header_len < 511) {
            strncpy(request->headers[request->header_count], header_start, header_len);
            request->headers[request->header_count][header_len] = '\0';
            
            // Check for Content-Type
            if (strncasecmp(header_start, "Content-Type:", 13) == 0) {
                const char *ct_start = header_start + 13;
                while (*ct_start == ' ') ct_start++;
                size_t ct_len = line_end - ct_start;
                if (ct_len < 127) {
                    strncpy(request->content_type, ct_start, ct_len);
                    request->content_type[ct_len] = '\0';
                }
            }
            
            request->header_count++;
            if (request->header_count >= MAX_HEADERS) break;
        }
        
        header_start = line_end + 2;
    }
    
    // Find body
    const char *body_start = strstr(raw_request, "\r\n\r\n");
    if (body_start) {
        body_start += 4;
        request->body_len = strlen(body_start);
        if (request->body_len > 0) {
            request->body = malloc(request->body_len + 1);
            strcpy(request->body, body_start);
        }
    }
    
    return 0;
}

// Build HTTP response
char* build_http_response(HttpResponse *response) {
    char headers[1024];
    sprintf(headers,
            "HTTP/1.1 %d %s\r\n"
            "Content-Type: %s\r\n"
            "Content-Length: %zu\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "Access-Control-Allow-Methods: GET, POST, DELETE, OPTIONS\r\n"
            "Access-Control-Allow-Headers: Content-Type\r\n"
            "\r\n",
            response->status_code,
            response->status_text,
            response->content_type,
            response->body_len);
    
    size_t total_len = strlen(headers) + response->body_len;
    char *full_response = malloc(total_len + 1);
    strcpy(full_response, headers);
    
    if (response->body && response->body_len > 0) {
        memcpy(full_response + strlen(headers), response->body, response->body_len);
    }
    
    full_response[total_len] = '\0';
    return full_response;
}

// Handle /api/quantum/keygen endpoint
void handle_keygen(HttpRequest *req, HttpResponse *res) {
    if (!req->body) {
        res->status_code = 400;
        strcpy(res->status_text, "Bad Request");
        res->body = create_error_response("Missing request body", 400);
        res->body_len = strlen(res->body);
        return;
    }
    
    char *user_id = json_get_string(req->body, "user_id");
    char *key_type = json_get_string(req->body, "key_type");
    
    if (!user_id) {
        res->status_code = 400;
        strcpy(res->status_text, "Bad Request");
        res->body = create_error_response("Missing user_id", 400);
        res->body_len = strlen(res->body);
        if (key_type) free(key_type);
        return;
    }
    
    if (!key_type) {
        key_type = strdup("all");
    }
    
    // Create or get session
    SessionKeys *session = create_session(user_id);
    if (!session) {
        res->status_code = 500;
        strcpy(res->status_text, "Internal Server Error");
        res->body = create_error_response("Failed to create session", 500);
        res->body_len = strlen(res->body);
        free(user_id);
        free(key_type);
        return;
    }
    
    char *response_json = json_create_object();
    json_add_string(&response_json, "user_id", user_id);
    
    char *keys_json = json_create_object();
    
    // Generate ML-KEM keys
    if (strcmp(key_type, "all") == 0 || strcmp(key_type, "kem") == 0) {
        if (generate_ml_kem_keypair(&session->ml_kem_public, &session->ml_kem_public_size,
                                    &session->ml_kem_private, &session->ml_kem_private_size) == 0) {
            char *ml_kem_obj = json_create_object();
            char *public_b64 = base64_encode(session->ml_kem_public, session->ml_kem_public_size);
            json_add_string(&ml_kem_obj, "public", public_b64);
            json_add_int(&ml_kem_obj, "public_size", session->ml_kem_public_size);
            json_close_object(&ml_kem_obj);
            json_add_object(&keys_json, "ml_kem", ml_kem_obj);
            free(public_b64);
            free(ml_kem_obj);
        }
    }
    
    // Generate Falcon keys
    if (strcmp(key_type, "all") == 0 || strcmp(key_type, "sig") == 0) {
        if (generate_falcon_keypair(&session->falcon_public, &session->falcon_public_size,
                                   &session->falcon_private, &session->falcon_private_size) == 0) {
            char *falcon_obj = json_create_object();
            char *public_b64 = base64_encode(session->falcon_public, session->falcon_public_size);
            json_add_string(&falcon_obj, "public", public_b64);
            json_add_int(&falcon_obj, "public_size", session->falcon_public_size);
            json_close_object(&falcon_obj);
            json_add_object(&keys_json, "falcon", falcon_obj);
            free(public_b64);
            free(falcon_obj);
        }
    }
    
    // Generate ECDSA keys
    if (strcmp(key_type, "all") == 0 || strcmp(key_type, "ecdsa") == 0) {
        if (generate_ecdsa_keypair(&session->ecdsa_public, &session->ecdsa_public_size,
                                  &session->ecdsa_private, &session->ecdsa_private_size) == 0) {
            char *ecdsa_obj = json_create_object();
            char *public_b64 = base64_encode(session->ecdsa_public, session->ecdsa_public_size);
            json_add_string(&ecdsa_obj, "public", public_b64);
            json_add_int(&ecdsa_obj, "public_size", session->ecdsa_public_size);
            json_close_object(&ecdsa_obj);
            json_add_object(&keys_json, "ecdsa", ecdsa_obj);
            free(public_b64);
            free(ecdsa_obj);
        }
    }
    
    json_close_object(&keys_json);
    json_add_object(&response_json, "keys", keys_json);
    json_add_string(&response_json, "quantum_implementation", "REAL");
    json_close_object(&response_json);
    
    res->status_code = 200;
    strcpy(res->status_text, "OK");
    res->body = response_json;
    res->body_len = strlen(response_json);
    
    free(user_id);
    free(key_type);
    free(keys_json);
}

// Handle /api/quantum/encapsulate endpoint
void handle_encapsulate(HttpRequest *req, HttpResponse *res) {
    if (!req->body) {
        res->status_code = 400;
        strcpy(res->status_text, "Bad Request");
        res->body = create_error_response("Missing request body", 400);
        res->body_len = strlen(res->body);
        return;
    }
    
    char *receiver_public_key_b64 = json_get_string(req->body, "receiver_public_key");
    if (!receiver_public_key_b64) {
        res->status_code = 400;
        strcpy(res->status_text, "Bad Request");
        res->body = create_error_response("Missing receiver_public_key", 400);
        res->body_len = strlen(res->body);
        return;
    }
    
    size_t public_key_len;
    uint8_t *public_key = base64_decode(receiver_public_key_b64, &public_key_len);
    free(receiver_public_key_b64);
    
    if (public_key_len != ML_KEM_768_PUBLIC_KEY_SIZE) {
        res->status_code = 400;
        strcpy(res->status_text, "Bad Request");
        res->body = create_error_response("Invalid public key size", 400);
        res->body_len = strlen(res->body);
        free(public_key);
        return;
    }
    
    uint8_t *ciphertext, *shared_secret;
    size_t ciphertext_len, shared_secret_len;
    
    if (ml_kem_encapsulate(public_key, public_key_len, &ciphertext, &ciphertext_len,
                          &shared_secret, &shared_secret_len) != 0) {
        res->status_code = 500;
        strcpy(res->status_text, "Internal Server Error");
        res->body = create_error_response("Encapsulation failed", 500);
        res->body_len = strlen(res->body);
        free(public_key);
        return;
    }
    
    char *response_json = json_create_object();
    char *ciphertext_b64 = base64_encode(ciphertext, ciphertext_len);
    char *shared_secret_b64 = base64_encode(shared_secret, shared_secret_len);
    
    json_add_string(&response_json, "ciphertext", ciphertext_b64);
    json_add_string(&response_json, "shared_secret", shared_secret_b64);
    json_add_string(&response_json, "algorithm", "ML-KEM-768");
    json_add_int(&response_json, "ciphertext_size", ciphertext_len);
    json_add_int(&response_json, "shared_secret_size", shared_secret_len);
    json_close_object(&response_json);
    
    res->status_code = 200;
    strcpy(res->status_text, "OK");
    res->body = response_json;
    res->body_len = strlen(response_json);
    
    free(public_key);
    free(ciphertext);
    free(shared_secret);
    free(ciphertext_b64);
    free(shared_secret_b64);
}

// Handle /api/quantum/decapsulate endpoint
void handle_decapsulate(HttpRequest *req, HttpResponse *res) {
    if (!req->body) {
        res->status_code = 400;
        strcpy(res->status_text, "Bad Request");
        res->body = create_error_response("Missing request body", 400);
        res->body_len = strlen(res->body);
        return;
    }
    
    char *ciphertext_b64 = json_get_string(req->body, "ciphertext");
    char *user_id = json_get_string(req->body, "user_id");
    
    if (!ciphertext_b64 || !user_id) {
        res->status_code = 400;
        strcpy(res->status_text, "Bad Request");
        res->body = create_error_response("Missing required parameters", 400);
        res->body_len = strlen(res->body);
        if (ciphertext_b64) free(ciphertext_b64);
        if (user_id) free(user_id);
        return;
    }
    
    SessionKeys *session = get_session(user_id);
    if (!session || !session->ml_kem_private) {
        res->status_code = 404;
        strcpy(res->status_text, "Not Found");
        res->body = create_error_response("No ML-KEM keys found for user", 404);
        res->body_len = strlen(res->body);
        free(ciphertext_b64);
        free(user_id);
        return;
    }
    
    size_t ciphertext_len;
    uint8_t *ciphertext = base64_decode(ciphertext_b64, &ciphertext_len);
    free(ciphertext_b64);
    
    if (ciphertext_len != ML_KEM_768_CIPHERTEXT_SIZE) {
        res->status_code = 400;
        strcpy(res->status_text, "Bad Request");
        res->body = create_error_response("Invalid ciphertext size", 400);
        res->body_len = strlen(res->body);
        free(ciphertext);
        free(user_id);
        return;
    }
    
    uint8_t *shared_secret;
    size_t shared_secret_len;
    
    if (ml_kem_decapsulate(ciphertext, ciphertext_len, session->ml_kem_private,
                          session->ml_kem_private_size, &shared_secret, &shared_secret_len) != 0) {
        res->status_code = 500;
        strcpy(res->status_text, "Internal Server Error");
        res->body = create_error_response("Decapsulation failed", 500);
        res->body_len = strlen(res->body);
        free(ciphertext);
        free(user_id);
        return;
    }
    
    char *response_json = json_create_object();
    char *shared_secret_b64 = base64_encode(shared_secret, shared_secret_len);
    
    json_add_string(&response_json, "shared_secret", shared_secret_b64);
    json_add_string(&response_json, "algorithm", "ML-KEM-768");
    json_add_int(&response_json, "shared_secret_size", shared_secret_len);
    json_close_object(&response_json);
    
    res->status_code = 200;
    strcpy(res->status_text, "OK");
    res->body = response_json;
    res->body_len = strlen(response_json);
    
    free(ciphertext);
    free(shared_secret);
    free(shared_secret_b64);
    free(user_id);
}// Handle /api/quantum/encrypt endpoint
void handle_encrypt(HttpRequest *req, HttpResponse *res) {
    if (!req->body) {
        res->status_code = 400;
        strcpy(res->status_text, "Bad Request");
        res->body = create_error_response("Missing request body", 400);
        res->body_len = strlen(res->body);
        return;
    }
    
    char *shared_secret_b64 = json_get_string(req->body, "shared_secret");
    char *plaintext = json_get_string(req->body, "plaintext");
    char *aad = json_get_string(req->body, "aad");
    
    if (!shared_secret_b64 || !plaintext) {
        res->status_code = 400;
        strcpy(res->status_text, "Bad Request");
        res->body = create_error_response("Missing required parameters", 400);
        res->body_len = strlen(res->body);
        if (shared_secret_b64) free(shared_secret_b64);
        if (plaintext) free(plaintext);
        if (aad) free(aad);
        return;
    }
    
    size_t key_len;
    uint8_t *key = base64_decode(shared_secret_b64, &key_len);
    free(shared_secret_b64);
    
    uint8_t *ciphertext, *nonce, *tag;
    size_t ciphertext_len;
    
    int result = aes_gcm_encrypt((uint8_t*)plaintext, strlen(plaintext),
                                 key, key_len,
                                 aad ? (uint8_t*)aad : NULL, aad ? strlen(aad) : 0,
                                 &ciphertext, &ciphertext_len, &nonce, &tag);
    
    free(plaintext);
    if (aad) free(aad);
    free(key);
    
    if (result != 0) {
        res->status_code = 500;
        strcpy(res->status_text, "Internal Server Error");
        res->body = create_error_response("Encryption failed", 500);
        res->body_len = strlen(res->body);
        return;
    }
    
    char *response_json = json_create_object();
    char *ciphertext_b64 = base64_encode(ciphertext, ciphertext_len);
    char *nonce_b64 = base64_encode(nonce, AES_GCM_IV_SIZE);
    char *tag_b64 = base64_encode(tag, AES_GCM_TAG_SIZE);
    
    json_add_string(&response_json, "ciphertext", ciphertext_b64);
    json_add_string(&response_json, "nonce", nonce_b64);
    json_add_string(&response_json, "tag", tag_b64);
    json_add_string(&response_json, "algorithm", "AES-256-GCM");
    json_add_int(&response_json, "ciphertext_size", ciphertext_len);
    json_close_object(&response_json);
    
    res->status_code = 200;
    strcpy(res->status_text, "OK");
    res->body = response_json;
    res->body_len = strlen(response_json);
    
    free(ciphertext);
    free(nonce);
    free(tag);
    free(ciphertext_b64);
    free(nonce_b64);
    free(tag_b64);
}

// Handle /api/quantum/decrypt endpoint
void handle_decrypt(HttpRequest *req, HttpResponse *res) {
    if (!req->body) {
        res->status_code = 400;
        strcpy(res->status_text, "Bad Request");
        res->body = create_error_response("Missing request body", 400);
        res->body_len = strlen(res->body);
        return;
    }
    
    char *shared_secret_b64 = json_get_string(req->body, "shared_secret");
    char *ciphertext_b64 = json_get_string(req->body, "ciphertext");
    char *nonce_b64 = json_get_string(req->body, "nonce");
    char *tag_b64 = json_get_string(req->body, "tag");
    char *aad = json_get_string(req->body, "aad");
    
    if (!shared_secret_b64 || !ciphertext_b64 || !nonce_b64 || !tag_b64) {
        res->status_code = 400;
        strcpy(res->status_text, "Bad Request");
        res->body = create_error_response("Missing required parameters", 400);
        res->body_len = strlen(res->body);
        if (shared_secret_b64) free(shared_secret_b64);
        if (ciphertext_b64) free(ciphertext_b64);
        if (nonce_b64) free(nonce_b64);
        if (tag_b64) free(tag_b64);
        if (aad) free(aad);
        return;
    }
    
    size_t key_len, ciphertext_len, nonce_len, tag_len;
    uint8_t *key = base64_decode(shared_secret_b64, &key_len);
    uint8_t *ciphertext = base64_decode(ciphertext_b64, &ciphertext_len);
    uint8_t *nonce = base64_decode(nonce_b64, &nonce_len);
    uint8_t *tag = base64_decode(tag_b64, &tag_len);
    
    free(shared_secret_b64);
    free(ciphertext_b64);
    free(nonce_b64);
    free(tag_b64);
    
    uint8_t *plaintext;
    size_t plaintext_len;
    
    int result = aes_gcm_decrypt(ciphertext, ciphertext_len,
                                 key, key_len,
                                 nonce, tag,
                                 aad ? (uint8_t*)aad : NULL, aad ? strlen(aad) : 0,
                                 &plaintext, &plaintext_len);
    
    free(key);
    free(ciphertext);
    free(nonce);
    free(tag);
    if (aad) free(aad);
    
    if (result != 0) {
        res->status_code = 400;
        strcpy(res->status_text, "Bad Request");
        res->body = create_error_response("Decryption failed", 400);
        res->body_len = strlen(res->body);
        return;
    }
    
    char *response_json = json_create_object();
    plaintext[plaintext_len] = '\0';  // Ensure null termination
    json_add_string(&response_json, "plaintext", (char*)plaintext);
    json_add_string(&response_json, "algorithm", "AES-256-GCM");
    json_close_object(&response_json);
    
    res->status_code = 200;
    strcpy(res->status_text, "OK");
    res->body = response_json;
    res->body_len = strlen(response_json);
    
    free(plaintext);
}

// Handle /api/quantum/info endpoint
void handle_info(HttpRequest *req, HttpResponse *res) {
    char *response_json = json_create_object();
    
    json_add_string(&response_json, "status", "operational");
    json_add_string(&response_json, "mode", "REAL QUANTUM CRYPTOGRAPHY");
    json_add_bool(&response_json, "quantum_ready", true);
    json_add_string(&response_json, "quantum_version", "liboqs 0.7.2");
    
    // Add algorithm details
    char *algorithms_json = json_create_object();
    
    char *kem_json = json_create_object();
    json_add_string(&kem_json, "name", "ML-KEM-768 (Kyber768)");
    json_add_int(&kem_json, "public_key_size", ML_KEM_768_PUBLIC_KEY_SIZE);
    json_add_int(&kem_json, "private_key_size", ML_KEM_768_PRIVATE_KEY_SIZE);
    json_add_int(&kem_json, "ciphertext_size", ML_KEM_768_CIPHERTEXT_SIZE);
    json_add_int(&kem_json, "shared_secret_size", ML_KEM_768_SHARED_SECRET_SIZE);
    json_add_string(&kem_json, "security_level", "NIST Level 3");
    json_close_object(&kem_json);
    json_add_object(&algorithms_json, "kem", kem_json);
    
    char *sig_json = json_create_object();
    json_add_string(&sig_json, "name", "Falcon-512");
    json_add_int(&sig_json, "public_key_size", FALCON_512_PUBLIC_KEY_SIZE);
    json_add_int(&sig_json, "private_key_size", FALCON_512_PRIVATE_KEY_SIZE);
    json_add_string(&sig_json, "signature_size", "600-800 bytes");
    json_add_string(&sig_json, "security_level", "NIST Level 1");
    json_close_object(&sig_json);
    json_add_object(&algorithms_json, "sig", sig_json);
    
    char *wrapper_json = json_create_object();
    json_add_string(&wrapper_json, "name", "ECDSA-P256");
    json_add_string(&wrapper_json, "curve", "NIST P-256 (secp256r1)");
    json_add_string(&wrapper_json, "signature_size", "64-72 bytes");
    json_close_object(&wrapper_json);
    json_add_object(&algorithms_json, "wrapper", wrapper_json);
    
    json_close_object(&algorithms_json);
    json_add_object(&response_json, "algorithms", algorithms_json);
    
    // Add server info
    time_t now = time(NULL);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));
    json_add_string(&response_json, "server_time", timestamp);
    json_add_int(&response_json, "uptime_seconds", (int)(now - start_time));
    json_add_string(&response_json, "api_version", "3.0.0");
    json_add_string(&response_json, "documentation", "/docs");
    
    json_close_object(&response_json);
    
    res->status_code = 200;
    strcpy(res->status_text, "OK");
    res->body = response_json;
    res->body_len = strlen(response_json);
    
    free(kem_json);
    free(sig_json);
    free(wrapper_json);
    free(algorithms_json);
}

// Handle /api/health endpoint
void handle_health(HttpRequest *req, HttpResponse *res) {
    char *response_json = json_create_object();
    
    json_add_string(&response_json, "status", "healthy");
    json_add_string(&response_json, "service", "Quantum Crypto Service");
    json_add_string(&response_json, "mode", "REAL");
    json_add_string(&response_json, "quantum_library", "liboqs");
    json_add_string(&response_json, "version", "3.0.0");
    
    time_t now = time(NULL);
    json_add_int(&response_json, "uptime_seconds", (int)(now - start_time));
    
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));
    json_add_string(&response_json, "timestamp", timestamp);
    
    json_close_object(&response_json);
    
    res->status_code = 200;
    strcpy(res->status_text, "OK");
    res->body = response_json;
    res->body_len = strlen(response_json);
}

// Handle client connection
void* handle_client(void* arg) {
    int client_socket = *(int*)arg;
    free(arg);
    
    char buffer[BUFFER_SIZE];
    memset(buffer, 0, BUFFER_SIZE);
    
    // Read request
    ssize_t bytes_read = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
    if (bytes_read <= 0) {
        close(client_socket);
        return NULL;
    }
    
    // Parse request
    HttpRequest request;
    if (parse_http_request(buffer, &request) != 0) {
        const char *error_response = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
        send(client_socket, error_response, strlen(error_response), 0);
        close(client_socket);
        return NULL;
    }
    
    // Initialize response
    HttpResponse response;
    memset(&response, 0, sizeof(HttpResponse));
    strcpy(response.content_type, "application/json");
    
    // Handle CORS preflight
    if (strcmp(request.method, "OPTIONS") == 0) {
        response.status_code = 200;
        strcpy(response.status_text, "OK");
        response.body = "";
        response.body_len = 0;
    }
    // Route to appropriate handler
    else if (strcmp(request.method, "POST") == 0) {
        if (strcmp(request.path, "/api/quantum/keygen") == 0) {
            handle_keygen(&request, &response);
        } else if (strcmp(request.path, "/api/quantum/encapsulate") == 0) {
            handle_encapsulate(&request, &response);
        } else if (strcmp(request.path, "/api/quantum/decapsulate") == 0) {
            handle_decapsulate(&request, &response);
        } else if (strcmp(request.path, "/api/quantum/encrypt") == 0) {
            handle_encrypt(&request, &response);
        } else if (strcmp(request.path, "/api/quantum/decrypt") == 0) {
            handle_decrypt(&request, &response);
        } else {
            response.status_code = 404;
            strcpy(response.status_text, "Not Found");
            response.body = create_error_response("Endpoint not found", 404);
            response.body_len = strlen(response.body);
        }
    } else if (strcmp(request.method, "GET") == 0) {
        if (strcmp(request.path, "/api/quantum/info") == 0) {
            handle_info(&request, &response);
        } else if (strcmp(request.path, "/api/health") == 0) {
            handle_health(&request, &response);
        } else {
            response.status_code = 404;
            strcpy(response.status_text, "Not Found");
            response.body = create_error_response("Endpoint not found", 404);
            response.body_len = strlen(response.body);
        }
    } else {
        response.status_code = 405;
        strcpy(response.status_text, "Method Not Allowed");
        response.body = create_error_response("Method not allowed", 405);
        response.body_len = strlen(response.body);
    }
    
    // Send response
    char *http_response = build_http_response(&response);
    send(client_socket, http_response, strlen(http_response), 0);
    
    // Cleanup
    free(http_response);
    if (response.body && strlen(response.body) > 0) {
        free(response.body);
    }
    if (request.body) {
        free(request.body);
    }
    
    close(client_socket);
    return NULL;
}

int main() {
    // Initialize quantum crypto
    if (init_quantum_crypto() != 0) {
        fprintf(stderr, "Failed to initialize quantum crypto\n");
        return 1;
    }
    
    // Set up signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Create socket
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        perror("Socket creation failed");
        cleanup_quantum_crypto();
        return 1;
    }
    
    // Allow socket reuse
    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt failed");
        close(server_socket);
        cleanup_quantum_crypto();
        return 1;
    }
    
    // Bind socket
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);
    
    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(server_socket);
        cleanup_quantum_crypto();
        return 1;
    }
    
    // Listen for connections
    if (listen(server_socket, 10) < 0) {
        perror("Listen failed");
        close(server_socket);
        cleanup_quantum_crypto();
        return 1;
    }
    
    start_time = time(NULL);
    
    printf("\n");
    printf("================================================================================\n");
    printf("QUANTUM CRYPTO SERVICE - C IMPLEMENTATION - v3.0.0\n");
    printf("================================================================================\n");
    printf("✅ RUNNING WITH REAL QUANTUM CRYPTOGRAPHY\n");
    printf("✅ liboqs enabled\n");
    printf("================================================================================\n");
    printf("Algorithms:\n");
    printf("  • Key Exchange: ML-KEM-768 (Kyber768) - NIST Level 3\n");
    printf("  • Digital Signature: Falcon-512 - NIST Level 1\n");
    printf("  • Wrapper Signature: ECDSA-P256\n");
    printf("  • Symmetric Encryption: AES-256-GCM\n");
    printf("  • Key Derivation: HKDF-SHA256\n");
    printf("================================================================================\n");
    printf("Starting server on http://localhost:%d\n", PORT);
    printf("================================================================================\n\n");
    
    // Accept connections
    while (running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        int *client_socket = malloc(sizeof(int));
        *client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_len);
        
        if (*client_socket < 0) {
            if (running) {
                perror("Accept failed");
            }
            free(client_socket);
            continue;
        }
        
        // Handle client in new thread
        pthread_t thread;
        pthread_create(&thread, NULL, handle_client, client_socket);
        pthread_detach(thread);
    }
    
    // Cleanup
    close(server_socket);
    cleanup_quantum_crypto();
    
    printf("✅ Server shut down successfully\n");
    return 0;
}