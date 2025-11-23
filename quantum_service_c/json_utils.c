#include "json_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

// Create a new JSON object
char* json_create_object(void) {
    char *json = malloc(2);
    strcpy(json, "{");
    return json;
}

// Add a string field to JSON
void json_add_string(char **json, const char *key, const char *value) {
    size_t old_len = strlen(*json);
    size_t new_len = old_len + strlen(key) + strlen(value) + 10;
    *json = realloc(*json, new_len);
    
    if (old_len > 1) {
        strcat(*json, ",");
    }
    
    strcat(*json, "\"");
    strcat(*json, key);
    strcat(*json, "\":\"");
    
    // Escape special characters
    char *escaped = escape_json_string(value);
    strcat(*json, escaped);
    free(escaped);
    
    strcat(*json, "\"");
}

// Add an integer field to JSON
void json_add_int(char **json, const char *key, int value) {
    char buffer[32];
    sprintf(buffer, "%d", value);
    
    size_t old_len = strlen(*json);
    size_t new_len = old_len + strlen(key) + strlen(buffer) + 10;
    *json = realloc(*json, new_len);
    
    if (old_len > 1) {
        strcat(*json, ",");
    }
    
    strcat(*json, "\"");
    strcat(*json, key);
    strcat(*json, "\":");
    strcat(*json, buffer);
}

// Add a boolean field to JSON
void json_add_bool(char **json, const char *key, bool value) {
    const char *val_str = value ? "true" : "false";
    
    size_t old_len = strlen(*json);
    size_t new_len = old_len + strlen(key) + strlen(val_str) + 10;
    *json = realloc(*json, new_len);
    
    if (old_len > 1) {
        strcat(*json, ",");
    }
    
    strcat(*json, "\"");
    strcat(*json, key);
    strcat(*json, "\":");
    strcat(*json, val_str);
}

// Add an object field to JSON
void json_add_object(char **json, const char *key, const char *object) {
    size_t old_len = strlen(*json);
    size_t new_len = old_len + strlen(key) + strlen(object) + 10;
    *json = realloc(*json, new_len);
    
    if (old_len > 1) {
        strcat(*json, ",");
    }
    
    strcat(*json, "\"");
    strcat(*json, key);
    strcat(*json, "\":");
    strcat(*json, object);
}

// Add an array field to JSON
void json_add_array(char **json, const char *key, const char *array) {
    size_t old_len = strlen(*json);
    size_t new_len = old_len + strlen(key) + strlen(array) + 10;
    *json = realloc(*json, new_len);
    
    if (old_len > 1) {
        strcat(*json, ",");
    }
    
    strcat(*json, "\"");
    strcat(*json, key);
    strcat(*json, "\":");
    strcat(*json, array);
}

// Close JSON object
void json_close_object(char **json) {
    size_t len = strlen(*json);
    *json = realloc(*json, len + 2);
    strcat(*json, "}");
}

// Parse string value from JSON
char* json_get_string(const char *json, const char *key) {
    char search_key[256];
    sprintf(search_key, "\"%s\":", key);
    
    const char *start = strstr(json, search_key);
    if (!start) return NULL;
    
    start += strlen(search_key);
    while (*start == ' ') start++;
    
    if (*start != '"') return NULL;
    start++;
    
    const char *end = start;
    while (*end && *end != '"') {
        if (*end == '\\' && *(end + 1)) {
            end += 2;
        } else {
            end++;
        }
    }
    
    size_t len = end - start;
    char *result = malloc(len + 1);
    
    // Handle escape sequences
    size_t j = 0;
    for (size_t i = 0; i < len; i++) {
        if (start[i] == '\\' && i + 1 < len) {
            switch (start[i + 1]) {
                case '"': result[j++] = '"'; i++; break;
                case '\\': result[j++] = '\\'; i++; break;
                case '/': result[j++] = '/'; i++; break;
                case 'b': result[j++] = '\b'; i++; break;
                case 'f': result[j++] = '\f'; i++; break;
                case 'n': result[j++] = '\n'; i++; break;
                case 'r': result[j++] = '\r'; i++; break;
                case 't': result[j++] = '\t'; i++; break;
                default: result[j++] = start[i];
            }
        } else {
            result[j++] = start[i];
        }
    }
    result[j] = '\0';
    
    return result;
}

// Parse integer value from JSON
int json_get_int(const char *json, const char *key) {
    char search_key[256];
    sprintf(search_key, "\"%s\":", key);
    
    const char *start = strstr(json, search_key);
    if (!start) return 0;
    
    start += strlen(search_key);
    while (*start == ' ') start++;
    
    return atoi(start);
}

// Parse boolean value from JSON
bool json_get_bool(const char *json, const char *key) {
    char search_key[256];
    sprintf(search_key, "\"%s\":", key);
    
    const char *start = strstr(json, search_key);
    if (!start) return false;
    
    start += strlen(search_key);
    while (*start == ' ') start++;
    
    return strncmp(start, "true", 4) == 0;
}

// Parse object value from JSON
char* json_get_object(const char *json, const char *key) {
    char search_key[256];
    sprintf(search_key, "\"%s\":", key);
    
    const char *start = strstr(json, search_key);
    if (!start) return NULL;
    
    start += strlen(search_key);
    while (*start == ' ') start++;
    
    if (*start != '{') return NULL;
    
    int depth = 0;
    const char *end = start;
    while (*end) {
        if (*end == '{') depth++;
        else if (*end == '}') {
            depth--;
            if (depth == 0) {
                end++;
                break;
            }
        }
        end++;
    }
    
    size_t len = end - start;
    char *result = malloc(len + 1);
    strncpy(result, start, len);
    result[len] = '\0';
    
    return result;
}

// Parse array value from JSON
char* json_get_array(const char *json, const char *key) {
    char search_key[256];
    sprintf(search_key, "\"%s\":", key);
    
    const char *start = strstr(json, search_key);
    if (!start) return NULL;
    
    start += strlen(search_key);
    while (*start == ' ') start++;
    
    if (*start != '[') return NULL;
    
    int depth = 0;
    const char *end = start;
    while (*end) {
        if (*end == '[') depth++;
        else if (*end == ']') {
            depth--;
            if (depth == 0) {
                end++;
                break;
            }
        }
        end++;
    }
    
    size_t len = end - start;
    char *result = malloc(len + 1);
    strncpy(result, start, len);
    result[len] = '\0';
    
    return result;
}

// Create error response
char* create_error_response(const char *error, int status_code) {
    char *json = json_create_object();
    json_add_string(&json, "error", error);
    json_add_int(&json, "status_code", status_code);
    
    // Add timestamp
    time_t now = time(NULL);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));
    json_add_string(&json, "timestamp", timestamp);
    
    json_close_object(&json);
    return json;
}

// Create success response
char* create_success_response(const char *data) {
    if (data && data[0] == '{') {
        // Data is already a JSON object
        return strdup(data);
    }
    
    char *json = json_create_object();
    json_add_string(&json, "status", "success");
    if (data) {
        json_add_string(&json, "data", data);
    }
    json_close_object(&json);
    return json;
}

// Escape special characters in JSON string
char* escape_json_string(const char *str) {
    size_t len = strlen(str);
    char *escaped = malloc(len * 2 + 1); // Worst case: all chars need escaping
    size_t j = 0;
    
    for (size_t i = 0; i < len; i++) {
        switch (str[i]) {
            case '"': 
                escaped[j++] = '\\';
                escaped[j++] = '"';
                break;
            case '\\':
                escaped[j++] = '\\';
                escaped[j++] = '\\';
                break;
            case '/':
                escaped[j++] = '\\';
                escaped[j++] = '/';
                break;
            case '\b':
                escaped[j++] = '\\';
                escaped[j++] = 'b';
                break;
            case '\f':
                escaped[j++] = '\\';
                escaped[j++] = 'f';
                break;
            case '\n':
                escaped[j++] = '\\';
                escaped[j++] = 'n';
                break;
            case '\r':
                escaped[j++] = '\\';
                escaped[j++] = 'r';
                break;
            case '\t':
                escaped[j++] = '\\';
                escaped[j++] = 't';
                break;
            default:
                if (iscntrl(str[i])) {
                    // Escape control characters as \uXXXX
                    sprintf(escaped + j, "\\u%04x", (unsigned char)str[i]);
                    j += 6;
                } else {
                    escaped[j++] = str[i];
                }
        }
    }
    
    escaped[j] = '\0';
    return escaped;
}

// Free JSON memory
void free_json(char *json) {
    free(json);
}