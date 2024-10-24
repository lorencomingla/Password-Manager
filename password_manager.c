#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

// Function to handle errors
void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

// Function to encrypt the plaintext
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    // Create and initialize the context
    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    // Initialize the encryption operation with AES-128-CBC
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
        handleErrors();

    // Provide the plaintext to be encrypted, and obtain the encrypted output
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    // Finalize the encryption
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
    ciphertext_len += len;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

// Function to decrypt the ciphertext
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    // Create and initialize the context
    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    // Initialize the decryption operation with AES-128-CBC
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
        handleErrors();

    // Provide the ciphertext to be decrypted, and obtain the decrypted output
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    // Finalize the decryption
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
    plaintext_len += len;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

// Function to add a new password
void add_password() {
    char username[50];
    char password[50];
    unsigned char encrypted_password[128];
    unsigned char *key = (unsigned char *)"0123456789abcdef";
    unsigned char *iv = (unsigned char *)"0123456789abcdef";
    int encrypted_len;

    printf("Enter username: ");
    scanf("%s", username);
    printf("Enter password: ");
    scanf("%s", password);

    encrypted_len = encrypt((unsigned char *)password, strlen(password), key, iv, encrypted_password);

    FILE *file = fopen("passwords.txt", "a");
    if (file == NULL) {
        printf("Error opening file!\n");
        return;
    }

    fprintf(file, "%s ", username);
    for (int i = 0; i < encrypted_len; i++) {
        fprintf(file, "%02x", encrypted_password[i]);
    }
    fprintf(file, "\n");

    fclose(file);
    printf("Password added successfully.\n");
}

// Function to retrieve a password
void retrieve_password() {
    char username[50];
    unsigned char encrypted_password[128];
    unsigned char decrypted_password[128];
    unsigned char *key = (unsigned char *)"0123456789abcdef";
    unsigned char *iv = (unsigned char *)"0123456789abcdef";

    printf("Enter username to retrieve password: ");
    scanf("%s", username);

    FILE *file = fopen("passwords.txt", "r");
    if (file == NULL) {
        printf("Error opening file!\n");
        return;
    }

    char file_username[50];
    char encrypted_hex[256];
    while (fscanf(file, "%s %s", file_username, encrypted_hex) != EOF) {
        if (strcmp(username, file_username) == 0) {
            int len = strlen(encrypted_hex) / 2;
            for (int i = 0; i < len; i++) {
                sscanf(&encrypted_hex[2 * i], "%2hhx", &encrypted_password[i]);
            }

            int decrypted_len = decrypt(encrypted_password, len, key, iv, decrypted_password);
            decrypted_password[decrypted_len] = '\0';

            printf("Password for %s: %s\n", username, decrypted_password);
            fclose(file);
            return;
        }
    }

    printf("Username not found.\n");
    fclose(file);
}

// Function to view all stored usernames
void view_usernames() {
    FILE *file = fopen("passwords.txt", "r");
    if (file == NULL) {
        printf("Error opening file!\n");
        return;
    }

    char username[50];
    char encrypted_password[256];

    printf("Stored Usernames:\n");
    while (fscanf(file, "%s %s", username, encrypted_password) != EOF) {
        printf("%s\n", username);
    }

    fclose(file);
}

// Main function to display the menu and handle user choices
int main() {
    int choice;
    unsigned char master_password[50];

    printf("Enter the master password to access the password manager: ");
    scanf("%s", master_password);

    // Simple check for a master password
    if (strcmp((char *)master_password, "securepassword123") != 0) {
        printf("Access denied.\n");
        return 1;
    }

    printf("Access granted.\n");

    while (1) {
        printf("\nPassword Manager\n");
        printf("1. Add Password\n");
        printf("2. Retrieve Password\n");
        printf("3. View Usernames\n");
        printf("4. Exit\n");
        printf("Enter your choice: ");
        scanf("%d", &choice);

        switch (choice) {
            case 1:
                add_password();
                break;
            case 2:
                retrieve_password();
                break;
            case 3:
                view_usernames();
                break;
            case 4:
                printf("Exiting...\n");
                return 0;
            default:
                printf("Invalid choice. Please try again.\n");
        }
    }

    return 0;
}
