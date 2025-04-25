#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bcrypt.h>
#include <json-c/json.h>
#include <ctype.h>
#include <time.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

#define MAX_SERVICE_LEN 100
#define MAX_PASSWORD_LEN 100
#define STORAGE_FILE "passwords.json"
#define MIN_PASSWORD_LEN 8
#define KEY_SIZE 32  // 256 bits
#define IV_SIZE 16   // 128 bits

typedef struct {
    char service[MAX_SERVICE_LEN];
    char password_hash[BCRYPT_HASHSIZE];
} PasswordEntry;

typedef struct {
    PasswordEntry* entries;
    size_t count;
    size_t capacity;
    char master_hash[BCRYPT_HASHSIZE];
    EncryptionKey enc_key;
} PasswordManager;

typedef struct {
    unsigned char key[KEY_SIZE];
    unsigned char iv[IV_SIZE];
} EncryptionKey;

// Function prototypes
void init_password_manager(PasswordManager* manager);
void free_password_manager(PasswordManager* manager);
int load_data(PasswordManager* manager);
int save_data(PasswordManager* manager);
int set_master_password(PasswordManager* manager, const char* password);
int verify_master_password(PasswordManager* manager, const char* password);
int add_password(PasswordManager* manager, const char* service, const char* password);
const char* get_password(PasswordManager* manager, const char* service);
int verify_password(PasswordManager* manager, const char* service, const char* password);
void list_services(PasswordManager* manager);
int check_password_strength(const char* password);
void generate_password(char* password, size_t length);
void generate_encryption_key(EncryptionKey* key);
int encrypt_data(const unsigned char* data, size_t data_len, 
                const EncryptionKey* key, unsigned char* encrypted);
int decrypt_data(const unsigned char* encrypted, size_t encrypted_len,
                const EncryptionKey* key, unsigned char* decrypted);

void init_password_manager(PasswordManager* manager) {
    manager->entries = NULL;
    manager->count = 0;
    manager->capacity = 0;
    memset(manager->master_hash, 0, BCRYPT_HASHSIZE);
    generate_encryption_key(&manager->enc_key);
    load_data(manager);
}

void free_password_manager(PasswordManager* manager) {
    free(manager->entries);
    manager->entries = NULL;
    manager->count = 0;
    manager->capacity = 0;
}

int load_data(PasswordManager* manager) {
    FILE* file = fopen(STORAGE_FILE, "r");
    if (!file) {
        return 0; // File doesn't exist yet
    }

    struct json_object* root = json_object_from_file(STORAGE_FILE);
    if (!root) {
        fclose(file);
        return 0;
    }

    // Load master password hash
    struct json_object* master_hash_obj;
    if (json_object_object_get_ex(root, "master_hash", &master_hash_obj)) {
        const char* master_hash = json_object_get_string(master_hash_obj);
        strncpy(manager->master_hash, master_hash, BCRYPT_HASHSIZE - 1);
    }

    // Load encryption key and IV
    struct json_object* enc_key_obj;
    if (json_object_object_get_ex(root, "encryption_key", &enc_key_obj) &&
        json_object_object_get_ex(root, "iv", &enc_key_obj)) {
        const char* enc_key_hex = json_object_get_string(enc_key_obj);
        const char* iv_hex = json_object_get_string(enc_key_obj);
        for (int i = 0; i < KEY_SIZE; i++) {
            sscanf(enc_key_hex + i * 2, "%02x", &manager->enc_key.key[i]);
        }
        for (int i = 0; i < IV_SIZE; i++) {
            sscanf(iv_hex + i * 2, "%02x", &manager->enc_key.iv[i]);
        }
    }

    // Load passwords
    struct json_object* passwords_obj;
    if (json_object_object_get_ex(root, "passwords", &passwords_obj)) {
        size_t num_entries = json_object_array_length(passwords_obj);
        manager->entries = realloc(manager->entries, num_entries * sizeof(PasswordEntry));
        manager->capacity = num_entries;

        for (size_t i = 0; i < num_entries; i++) {
            struct json_object* entry = json_object_array_get_idx(passwords_obj, i);
            struct json_object* service_obj, *hash_obj;

            if (json_object_object_get_ex(entry, "service", &service_obj) &&
                json_object_object_get_ex(entry, "hash", &hash_obj)) {
                char service_hex[MAX_SERVICE_LEN * 2 + 1];
                char hash_hex[BCRYPT_HASHSIZE * 2 + 1];
                strncpy(service_hex, json_object_get_string(service_obj), MAX_SERVICE_LEN * 2);
                strncpy(hash_hex, json_object_get_string(hash_obj), BCRYPT_HASHSIZE * 2);
                service_hex[MAX_SERVICE_LEN * 2] = '\0';
                hash_hex[BCRYPT_HASHSIZE * 2] = '\0';
                strncpy(manager->entries[i].service, service_hex, MAX_SERVICE_LEN - 1);
                strncpy(manager->entries[i].password_hash, hash_hex, BCRYPT_HASHSIZE - 1);
                manager->count++;
            }
        }
    }

    json_object_put(root);
    fclose(file);
    return 1;
}

int save_data(PasswordManager* manager) {
    struct json_object* root = json_object_new_object();
    
    // Save master password hash
    json_object_object_add(root, "master_hash", 
                          json_object_new_string(manager->master_hash));

    // Save encryption key and IV
    char key_hex[KEY_SIZE * 2 + 1];
    char iv_hex[IV_SIZE * 2 + 1];
    for (int i = 0; i < KEY_SIZE; i++) {
        sprintf(key_hex + i * 2, "%02x", manager->enc_key.key[i]);
    }
    for (int i = 0; i < IV_SIZE; i++) {
        sprintf(iv_hex + i * 2, "%02x", manager->enc_key.iv[i]);
    }
    json_object_object_add(root, "encryption_key", json_object_new_string(key_hex));
    json_object_object_add(root, "iv", json_object_new_string(iv_hex));

    // Save encrypted passwords
    struct json_object* passwords_array = json_object_new_array();
    for (size_t i = 0; i < manager->count; i++) {
        struct json_object* entry = json_object_new_object();
        
        // Encrypt service name and password hash
        unsigned char encrypted_service[MAX_SERVICE_LEN + AES_BLOCK_SIZE];
        unsigned char encrypted_hash[BCRYPT_HASHSIZE + AES_BLOCK_SIZE];
        
        int service_len = encrypt_data((unsigned char*)manager->entries[i].service,
                                     strlen(manager->entries[i].service),
                                     &manager->enc_key, encrypted_service);
        int hash_len = encrypt_data((unsigned char*)manager->entries[i].password_hash,
                                  strlen(manager->entries[i].password_hash),
                                  &manager->enc_key, encrypted_hash);
        
        char service_hex[service_len * 2 + 1];
        char hash_hex[hash_len * 2 + 1];
        
        for (int j = 0; j < service_len; j++) {
            sprintf(service_hex + j * 2, "%02x", encrypted_service[j]);
        }
        for (int j = 0; j < hash_len; j++) {
            sprintf(hash_hex + j * 2, "%02x", encrypted_hash[j]);
        }
        
        json_object_object_add(entry, "service", json_object_new_string(service_hex));
        json_object_object_add(entry, "hash", json_object_new_string(hash_hex));
        json_object_array_add(passwords_array, entry);
    }
    json_object_object_add(root, "passwords", passwords_array);

    // Write to file
    FILE* file = fopen(STORAGE_FILE, "w");
    if (!file) {
        json_object_put(root);
        return 0;
    }

    const char* json_string = json_object_to_json_string_ext(root, 
                                                           JSON_C_TO_STRING_PRETTY);
    fprintf(file, "%s", json_string);
    
    json_object_put(root);
    fclose(file);
    return 1;
}

int set_master_password(PasswordManager* manager, const char* password) {
    char salt[BCRYPT_HASHSIZE];
    if (bcrypt_gensalt(12, salt) != 0) {
        return 0;
    }
    
    if (bcrypt_hashpw(password, salt, manager->master_hash) != 0) {
        return 0;
    }
    
    return save_data(manager);
}

int verify_master_password(PasswordManager* manager, const char* password) {
    if (manager->master_hash[0] == '\0') {
        return 0;
    }
    return bcrypt_checkpw(password, manager->master_hash) == 0;
}

int check_password_strength(const char* password) {
    int has_upper = 0, has_lower = 0, has_digit = 0, has_special = 0;
    int len = strlen(password);
    
    if (len < MIN_PASSWORD_LEN) {
        printf("Password must be at least %d characters long\n", MIN_PASSWORD_LEN);
        return 0;
    }
    
    for (int i = 0; i < len; i++) {
        if (isupper(password[i])) has_upper = 1;
        else if (islower(password[i])) has_lower = 1;
        else if (isdigit(password[i])) has_digit = 1;
        else has_special = 1;
    }
    
    if (!has_upper || !has_lower || !has_digit || !has_special) {
        printf("Password must contain uppercase, lowercase, numbers, and special characters\n");
        return 0;
    }
    
    return 1;
}

int add_password(PasswordManager* manager, const char* service, const char* password) {
    // Check password strength
    if (!check_password_strength(password)) {
        return 0;
    }

    // Check if service already exists
    for (size_t i = 0; i < manager->count; i++) {
        if (strcmp(manager->entries[i].service, service) == 0) {
            printf("Service already exists. Use a different name.\n");
            return 0;
        }
    }

    // Resize array if needed
    if (manager->count >= manager->capacity) {
        size_t new_capacity = manager->capacity == 0 ? 1 : manager->capacity * 2;
        PasswordEntry* new_entries = realloc(manager->entries, 
                                           new_capacity * sizeof(PasswordEntry));
        if (!new_entries) {
            return 0;
        }
        manager->entries = new_entries;
        manager->capacity = new_capacity;
    }

    // Generate salt and hash password
    char salt[BCRYPT_HASHSIZE];
    if (bcrypt_gensalt(12, salt) != 0) {
        return 0;
    }

    strncpy(manager->entries[manager->count].service, service, MAX_SERVICE_LEN - 1);
    if (bcrypt_hashpw(password, salt, manager->entries[manager->count].password_hash) != 0) {
        return 0;
    }

    manager->count++;
    return save_data(manager);
}

const char* get_password(PasswordManager* manager, const char* service) {
    for (size_t i = 0; i < manager->count; i++) {
        if (strcmp(manager->entries[i].service, service) == 0) {
            return manager->entries[i].password_hash;
        }
    }
    return NULL;
}

int verify_password(PasswordManager* manager, const char* service, const char* password) {
    const char* stored_hash = get_password(manager, service);
    if (!stored_hash) {
        return 0;
    }
    return bcrypt_checkpw(password, stored_hash) == 0;
}

void list_services(PasswordManager* manager) {
    if (manager->count == 0) {
        printf("No services stored.\n");
        return;
    }

    printf("\nStored services:\n");
    for (size_t i = 0; i < manager->count; i++) {
        printf("- %s\n", manager->entries[i].service);
    }
}

void generate_password(char* password, size_t length) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?";
    const size_t charset_size = strlen(charset);
    
    srand(time(NULL));
    
    // Ensure at least one of each required character type
    password[0] = charset[rand() % 26];  // lowercase
    password[1] = charset[26 + rand() % 26];  // uppercase
    password[2] = charset[52 + rand() % 10];  // digit
    password[3] = charset[62 + rand() % (charset_size - 62)];  // special
    
    // Fill the rest randomly
    for (size_t i = 4; i < length; i++) {
        password[i] = charset[rand() % charset_size];
    }
    
    // Shuffle the password
    for (size_t i = length - 1; i > 0; i--) {
        size_t j = rand() % (i + 1);
        char temp = password[i];
        password[i] = password[j];
        password[j] = temp;
    }
    
    password[length] = '\0';
}

void generate_encryption_key(EncryptionKey* key) {
    if (RAND_bytes(key->key, KEY_SIZE) != 1) {
        fprintf(stderr, "Error generating encryption key\n");
        exit(1);
    }
    if (RAND_bytes(key->iv, IV_SIZE) != 1) {
        fprintf(stderr, "Error generating IV\n");
        exit(1);
    }
}

int encrypt_data(const unsigned char* data, size_t data_len, 
                const EncryptionKey* key, unsigned char* encrypted) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key->key, key->iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    int len;
    if (EVP_EncryptUpdate(ctx, encrypted, &len, data, data_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    int final_len;
    if (EVP_EncryptFinal_ex(ctx, encrypted + len, &final_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    EVP_CIPHER_CTX_free(ctx);
    return len + final_len;
}

int decrypt_data(const unsigned char* encrypted, size_t encrypted_len,
                const EncryptionKey* key, unsigned char* decrypted) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key->key, key->iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    int len;
    if (EVP_DecryptUpdate(ctx, decrypted, &len, encrypted, encrypted_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    int final_len;
    if (EVP_DecryptFinal_ex(ctx, decrypted + len, &final_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    EVP_CIPHER_CTX_free(ctx);
    return len + final_len;
}

int main() {
    PasswordManager manager;
    init_password_manager(&manager);

    // Set up master password if not already set
    if (manager.master_hash[0] == '\0') {
        printf("Welcome! Please set up your master password.\n");
        char password[MAX_PASSWORD_LEN];
        char confirm[MAX_PASSWORD_LEN];

        while (1) {
            printf("Enter master password: ");
            fgets(password, MAX_PASSWORD_LEN, stdin);
            password[strcspn(password, "\n")] = 0;

            printf("Confirm master password: ");
            fgets(confirm, MAX_PASSWORD_LEN, stdin);
            confirm[strcspn(confirm, "\n")] = 0;

            if (strcmp(password, confirm) == 0) {
                if (set_master_password(&manager, password)) {
                    printf("Master password set successfully!\n");
                    break;
                } else {
                    printf("Error setting master password. Try again.\n");
                }
            } else {
                printf("Passwords don't match. Try again.\n");
            }
        }
    }

    // Main program loop
    while (1) {
        printf("\nPassword Manager\n");
        printf("1. Add password\n");
        printf("2. Get password\n");
        printf("3. Verify password\n");
        printf("4. List services\n");
        printf("5. Generate strong password\n");
        printf("6. Exit\n");

        printf("\nEnter your choice (1-6): ");
        char choice[10];
        fgets(choice, sizeof(choice), stdin);
        choice[strcspn(choice, "\n")] = 0;

        if (strcmp(choice, "1") == 0) {
            char service[MAX_SERVICE_LEN];
            char password[MAX_PASSWORD_LEN];
            char generate[10];

            printf("Enter service name: ");
            fgets(service, MAX_SERVICE_LEN, stdin);
            service[strcspn(service, "\n")] = 0;

            printf("Generate strong password? (y/n): ");
            fgets(generate, sizeof(generate), stdin);
            generate[strcspn(generate, "\n")] = 0;

            if (strcmp(generate, "y") == 0 || strcmp(generate, "Y") == 0) {
                generate_password(password, 16);  // Generate 16-character password
                printf("Generated password: %s\n", password);
            } else {
                printf("Enter password: ");
                fgets(password, MAX_PASSWORD_LEN, stdin);
                password[strcspn(password, "\n")] = 0;
            }

            if (add_password(&manager, service, password)) {
                printf("Password added successfully!\n");
            } else {
                printf("Error adding password.\n");
            }
        }
        else if (strcmp(choice, "2") == 0) {
            char service[MAX_SERVICE_LEN];
            char master_password[MAX_PASSWORD_LEN];

            printf("Enter service name: ");
            fgets(service, MAX_SERVICE_LEN, stdin);
            service[strcspn(service, "\n")] = 0;

            printf("Enter master password: ");
            fgets(master_password, MAX_PASSWORD_LEN, stdin);
            master_password[strcspn(master_password, "\n")] = 0;

            if (verify_master_password(&manager, master_password)) {
                const char* stored_hash = get_password(&manager, service);
                if (stored_hash) {
                    printf("Stored hash for %s: %s\n", service, stored_hash);
                } else {
                    printf("Service not found.\n");
                }
            } else {
                printf("Invalid master password.\n");
            }
        }
        else if (strcmp(choice, "3") == 0) {
            char service[MAX_SERVICE_LEN];
            char password[MAX_PASSWORD_LEN];

            printf("Enter service name: ");
            fgets(service, MAX_SERVICE_LEN, stdin);
            service[strcspn(service, "\n")] = 0;

            printf("Enter password to verify: ");
            fgets(password, MAX_PASSWORD_LEN, stdin);
            password[strcspn(password, "\n")] = 0;

            if (verify_password(&manager, service, password)) {
                printf("Password verified successfully!\n");
            } else {
                printf("Invalid password or service not found.\n");
            }
        }
        else if (strcmp(choice, "4") == 0) {
            list_services(&manager);
        }
        else if (strcmp(choice, "5") == 0) {
            char password[MAX_PASSWORD_LEN];
            generate_password(password, 16);
            printf("Generated strong password: %s\n", password);
        }
        else if (strcmp(choice, "6") == 0) {
            printf("Goodbye!\n");
            break;
        }
        else {
            printf("Invalid choice. Please try again.\n");
        }
    }

    free_password_manager(&manager);
    return 0;
} 