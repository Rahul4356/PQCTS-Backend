#ifndef JSON_UTILS_H
#define JSON_UTILS_H

#include <stddef.h>
#include <stdbool.h>

// JSON helper functions
char* json_create_object(void);
void json_add_string(char **json, const char *key, const char *value);
void json_add_int(char **json, const char *key, int value);
void json_add_bool(char **json, const char *key, bool value);
void json_add_object(char **json, const char *key, const char *object);
void json_add_array(char **json, const char *key, const char *array);
void json_close_object(char **json);

// JSON parsing helpers
char* json_get_string(const char *json, const char *key);
int json_get_int(const char *json, const char *key);
bool json_get_bool(const char *json, const char *key);
char* json_get_object(const char *json, const char *key);
char* json_get_array(const char *json, const char *key);

// Error response creation
char* create_error_response(const char *error, int status_code);
char* create_success_response(const char *data);

// Utility functions
char* escape_json_string(const char *str);
void free_json(char *json);

#endif // JSON_UTILS_H