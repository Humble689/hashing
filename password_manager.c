#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bcrypt.h>
#include <json-c/json.h>

#define MAX_SERVICE_LEN 100
#define MAX_PASSWORD_LEN 100
#define STORAGE_FILE "passwords.json"

typedef struct {
    char service[MAX_SERVICE_LEN];
    char password_hash[BCRYPT_HASHSIZE];
} PasswordEntry;

typedef struct {
    PasswordEntry* entries;
    size_t count;
    size_t capacity;
    char master_hash[BCRYPT_HASHSIZE];
} PasswordManager;

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

void init_password_manager(PasswordManager* manager) {
    manager->entries = NULL;
    manager->count = 0;
    manager->capacity = 0;
    memset(manager->master_hash, 0, BCRYPT_HASHSIZE);
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
                strncpy(manager->entries[i].service, 
                       json_object_get_string(service_obj), 
                       MAX_SERVICE_LEN - 1);
                strncpy(manager->entries[i].password_hash, 
                       json_object_get_string(hash_obj), 
                       BCRYPT_HASHSIZE - 1);
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

    // Save passwords
    struct json_object* passwords_array = json_object_new_array();
    for (size_t i = 0; i < manager->count; i++) {
        struct json_object* entry = json_object_new_object();
        json_object_object_add(entry, "service", 
                             json_object_new_string(manager->entries[i].service));
        json_object_object_add(entry, "hash", 
                             json_object_new_string(manager->entries[i].password_hash));
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

int add_password(PasswordManager* manager, const char* service, const char* password) {
    // Check if service already exists
    for (size_t i = 0; i < manager->count; i++) {
        if (strcmp(manager->entries[i].service, service) == 0) {
            return 0; // Service already exists
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
        printf("5. Exit\n");

        printf("\nEnter your choice (1-5): ");
        char choice[10];
        fgets(choice, sizeof(choice), stdin);
        choice[strcspn(choice, "\n")] = 0;

        if (strcmp(choice, "1") == 0) {
            char service[MAX_SERVICE_LEN];
            char password[MAX_PASSWORD_LEN];

            printf("Enter service name: ");
            fgets(service, MAX_SERVICE_LEN, stdin);
            service[strcspn(service, "\n")] = 0;

            printf("Enter password: ");
            fgets(password, MAX_PASSWORD_LEN, stdin);
            password[strcspn(password, "\n")] = 0;

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