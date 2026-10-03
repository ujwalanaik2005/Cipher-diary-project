/* ============================================================
   CIPHER DIARY v2  (Final Year Project Edition)
   ------------------------------------------------------------
   Upgrades over the basic version:
     1. User accounts (register/login) so multiple people can
        use the same program, each with their own diary file.
     2. Login passwords are never stored in plain text -- a
        simple hash (djb2) is stored instead.
     3. A Vigenere-style cipher (addition mod 256) replaces the
        basic XOR cipher. It's a named, studied classical cipher
        -- easier to defend in a viva than raw XOR -- and works
        on ALL byte values (letters, numbers, punctuation),
        unlike the textbook A-Z-only Vigenere cipher.
     4. Password input is hidden (no echo) when run in a real
        terminal.
     5. Full CRUD: Add, View, Edit, Delete, Search entries.

   IMPORTANT ACADEMIC NOTE (for your report):
   This cipher is for LEARNING PURPOSES, not real-world security.
   It has no protection against frequency analysis if the key is
   short, and the hash used for login passwords is a simple
   non-cryptographic hash (djb2), not a secure password hash like
   bcrypt/Argon2. In your report's "Limitations & Future Work"
   section, you can mention upgrading to AES (via a library like
   OpenSSL) and a proper password hashing scheme as next steps.

   COMPILE:
       gcc cipher_diary_v2.c -o cipher_diary_v2
   RUN:
       ./cipher_diary_v2
   ============================================================ */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* termios.h/unistd.h are POSIX-only (Linux/Mac). On Windows we use
   conio.h instead, since MinGW doesn't ship a termios implementation.
   _WIN32 is a macro the compiler defines automatically on Windows,
   so this #ifdef picks the right code at compile time. */
#ifdef _WIN32
    #include <conio.h>
#else
    #include <termios.h>
    #include <unistd.h>
#endif

#define MAX_TEXT    2000
#define MAX_LINE    4200
#define MAX_ENTRIES 200
#define USERS_FILE  "users.txt"

/* ---------- Hide password input when typing (works on Windows AND Linux/Mac) ---------- */
void get_hidden_input(char *buf, int size) {
#ifdef _WIN32
    /* Windows version: read one key at a time with _getch(), which
       reads a key without echoing it to the screen or needing Enter
       to be pressed per character. We print '*' ourselves instead. */
    int i = 0;
    int ch;
    while (i < size - 1) {
        ch = _getch();
        if (ch == '\r' || ch == '\n') break;     /* Enter pressed */
        if (ch == '\b') {                        /* Backspace pressed */
            if (i > 0) {
                i--;
                printf("\b \b"); /* erase the last '*' on screen */
            }
            continue;
        }
        buf[i++] = (char)ch;
        printf("*");
    }
    buf[i] = '\0';
    printf("\n");
#else
    /* Linux/Mac version: temporarily turn off terminal echo */
    struct termios oldt, newt;
    int is_tty = (tcgetattr(STDIN_FILENO, &oldt) == 0);

    if (is_tty) {
        newt = oldt;
        newt.c_lflag &= ~(ECHO);            /* turn off echoing to screen */
        tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    }

    fgets(buf, size, stdin);
    buf[strcspn(buf, "\n")] = 0;            /* strip trailing newline */

    if (is_tty) {
        tcsetattr(STDIN_FILENO, TCSANOW, &oldt); /* restore echoing */
        printf("\n");
    }
#endif
}

/* ---------- Simple djb2 hash, used so we never store plain passwords ---------- */
unsigned long hash_password(const char *str) {
    unsigned long hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + (unsigned long)c; /* hash * 33 + c */
    }
    return hash;
}

/* ---------- Vigenere-style cipher (addition/subtraction mod 256) ----------
   encrypt=1: output[i] = (input[i] + key[i]) mod 256
   encrypt=0: output[i] = (input[i] - key[i] + 256) mod 256
   Unlike XOR, encrypting twice does NOT undo itself -- you must
   call this with encrypt=0 to reverse an encrypt=1 pass.
---------------------------------------------------------------- */
void vigenere_transform(const char *input, const char *key, char *output, int len, int encrypt) {
    int key_len = strlen(key);
    for (int i = 0; i < len; i++) {
        unsigned char in_byte  = (unsigned char)input[i];
        unsigned char key_byte = (unsigned char)key[i % key_len];
        if (encrypt) {
            output[i] = (char)((in_byte + key_byte) % 256);
        } else {
            output[i] = (char)(((in_byte - key_byte) + 256) % 256);
        }
    }
}

/* ---------- Byte <-> hex helpers (so encrypted bytes are file-safe) ---------- */
void bytes_to_hex(const char *data, int len, char *hex_out) {
    for (int i = 0; i < len; i++) {
        sprintf(hex_out + (i * 2), "%02X", (unsigned char)data[i]);
    }
    hex_out[len * 2] = '\0';
}

int hex_to_bytes(const char *hex, char *bytes_out) {
    int len = strlen(hex) / 2;
    for (int i = 0; i < len; i++) {
        sscanf(hex + (i * 2), "%2hhx", &bytes_out[i]);
    }
    return len;
}

void get_today(char *buf) {
    time_t t = time(NULL);
    struct tm *tm_info = localtime(&t);
    strftime(buf, 20, "%Y-%m-%d", tm_info);
}

/* ---------- Build "<username>_diary.txt" ---------- */
void get_diary_filename(const char *username, char *out) {
    sprintf(out, "%s_diary.txt", username);
}

/* ============================================================
   USER ACCOUNTS
   ============================================================ */

int user_exists(const char *username) {
    FILE *f = fopen(USERS_FILE, "r");
    if (!f) return 0;

    char line[200], uname[100];
    unsigned long stored_hash;
    while (fgets(line, sizeof(line), f)) {
        sscanf(line, "%99[^|]|%lu", uname, &stored_hash);
        if (strcmp(uname, username) == 0) {
            fclose(f);
            return 1;
        }
    }
    fclose(f);
    return 0;
}

void register_user() {
    char username[100], password[100];

    printf("Choose a username: ");
    fgets(username, sizeof(username), stdin);
    username[strcspn(username, "\n")] = 0;

    if (user_exists(username)) {
        printf("That username is already taken.\n");
        return;
    }

    printf("Choose a login password: ");
    get_hidden_input(password, sizeof(password));

    unsigned long hash = hash_password(password);

    FILE *f = fopen(USERS_FILE, "a");
    if (!f) {
        printf("Error: could not save user.\n");
        return;
    }
    fprintf(f, "%s|%lu\n", username, hash);
    fclose(f);

    printf("Registered successfully! You can now log in.\n");
}

/* Returns 1 and fills username_out on success, 0 on failure */
int login_user(char *username_out) {
    char username[100], password[100];

    printf("Username: ");
    fgets(username, sizeof(username), stdin);
    username[strcspn(username, "\n")] = 0;

    printf("Password: ");
    get_hidden_input(password, sizeof(password));

    unsigned long entered_hash = hash_password(password);

    FILE *f = fopen(USERS_FILE, "r");
    if (!f) {
        printf("No users registered yet.\n");
        return 0;
    }

    char line[200], uname[100];
    unsigned long stored_hash;
    while (fgets(line, sizeof(line), f)) {
        sscanf(line, "%99[^|]|%lu", uname, &stored_hash);
        if (strcmp(uname, username) == 0 && stored_hash == entered_hash) {
            fclose(f);
            strcpy(username_out, username);
            return 1;
        }
    }
    fclose(f);
    printf("Invalid username or password.\n");
    return 0;
}

/* ============================================================
   DIARY ENTRY OPERATIONS
   ============================================================ */

/* Loads all entries for a user into parallel arrays. Returns count. */
int load_entries(const char *username, char titles[][100], char dates[][20], char hexes[][MAX_TEXT * 2]) {
    char filename[150];
    get_diary_filename(username, filename);

    FILE *f = fopen(filename, "r");
    if (!f) return 0;

    char line[MAX_LINE];
    int count = 0;
    while (fgets(line, sizeof(line), f) && count < MAX_ENTRIES) {
        line[strcspn(line, "\n")] = 0;

        char *title = strtok(line, "|");
        char *date  = strtok(NULL, "|");
        char *hex   = strtok(NULL, "|");
        if (!title || !date || !hex) continue;

        strcpy(titles[count], title);
        strcpy(dates[count], date);
        strcpy(hexes[count], hex);
        count++;
    }
    fclose(f);
    return count;
}

/* Rewrites the ENTIRE diary file from the given arrays (used after edit/delete) */
void save_all_entries(const char *username, char titles[][100], char dates[][20], char hexes[][MAX_TEXT * 2], int count) {
    char filename[150];
    get_diary_filename(username, filename);

    FILE *f = fopen(filename, "w"); /* "w" = overwrite completely */
    if (!f) {
        printf("Error: could not save diary.\n");
        return;
    }
    for (int i = 0; i < count; i++) {
        fprintf(f, "%s|%s|%s\n", titles[i], dates[i], hexes[i]);
    }
    fclose(f);
}

void print_entry_list(char titles[][100], char dates[][20], int count) {
    printf("\n--- Your Entries ---\n");
    if (count == 0) {
        printf("No entries yet.\n");
        return;
    }
    for (int i = 0; i < count; i++) {
        printf("%d) %s  (%s)\n", i + 1, titles[i], dates[i]);
    }
}

void add_entry(const char *username) {
    char titles[MAX_ENTRIES][100], dates[MAX_ENTRIES][20], hexes[MAX_ENTRIES][MAX_TEXT * 2];
    int count = load_entries(username, titles, dates, hexes);

    if (count >= MAX_ENTRIES) {
        printf("Diary is full.\n");
        return;
    }

    char title[100], key[100], text[MAX_TEXT];

    printf("\n--- New Entry ---\n");
    printf("Title: ");
    fgets(title, sizeof(title), stdin);
    title[strcspn(title, "\n")] = 0;

    printf("Encryption key (can be different from your login password): ");
    get_hidden_input(key, sizeof(key));

    if (strlen(key) == 0) {
        printf("Key cannot be empty. Entry cancelled.\n");
        return;
    }

    printf("Write your entry (end with a line containing only END):\n");
    text[0] = '\0';
    char line[500];
    while (fgets(line, sizeof(line), stdin)) {
        if (strncmp(line, "END", 3) == 0) break;
        strncat(text, line, MAX_TEXT - strlen(text) - 1);
    }

    int len = strlen(text);
    char encrypted[MAX_TEXT];
    vigenere_transform(text, key, encrypted, len, 1);

    strcpy(titles[count], title);
    get_today(dates[count]);
    bytes_to_hex(encrypted, len, hexes[count]);
    count++;

    save_all_entries(username, titles, dates, hexes, count);
    printf("Entry saved and encrypted.\n");
}

void view_entry(const char *username) {
    char titles[MAX_ENTRIES][100], dates[MAX_ENTRIES][20], hexes[MAX_ENTRIES][MAX_TEXT * 2];
    int count = load_entries(username, titles, dates, hexes);
    print_entry_list(titles, dates, count);
    if (count == 0) return;

    printf("\nChoose entry number: ");
    int choice;
    scanf("%d", &choice);
    getchar(); /* consume leftover newline */
    if (choice < 1 || choice > count) {
        printf("Invalid choice.\n");
        return;
    }

    char key[100];
    printf("Encryption key: ");
    get_hidden_input(key, sizeof(key));

    char bytes[MAX_TEXT], decrypted[MAX_TEXT];
    int len = hex_to_bytes(hexes[choice - 1], bytes);
    vigenere_transform(bytes, key, decrypted, len, 0);
    decrypted[len] = '\0';

    printf("\n--- %s (%s) ---\n", titles[choice - 1], dates[choice - 1]);
    printf("%s\n", decrypted);
    printf("--------------------------\n");
    printf("(If the key was wrong, the text above will look like garbage.)\n");
}

void edit_entry(const char *username) {
    char titles[MAX_ENTRIES][100], dates[MAX_ENTRIES][20], hexes[MAX_ENTRIES][MAX_TEXT * 2];
    int count = load_entries(username, titles, dates, hexes);
    print_entry_list(titles, dates, count);
    if (count == 0) return;

    printf("\nChoose entry number to edit: ");
    int choice;
    scanf("%d", &choice);
    getchar();
    if (choice < 1 || choice > count) {
        printf("Invalid choice.\n");
        return;
    }
    int idx = choice - 1;

    char key[100];
    printf("Current encryption key (to confirm it's yours): ");
    get_hidden_input(key, sizeof(key));

    printf("New text (end with a line containing only END):\n");
    char text[MAX_TEXT];
    text[0] = '\0';
    char line[500];
    while (fgets(line, sizeof(line), stdin)) {
        if (strncmp(line, "END", 3) == 0) break;
        strncat(text, line, MAX_TEXT - strlen(text) - 1);
    }

    int len = strlen(text);
    char encrypted[MAX_TEXT];
    vigenere_transform(text, key, encrypted, len, 1);
    bytes_to_hex(encrypted, len, hexes[idx]);
    get_today(dates[idx]); /* update last-edited date */

    save_all_entries(username, titles, dates, hexes, count);
    printf("Entry updated.\n");
}

void delete_entry(const char *username) {
    char titles[MAX_ENTRIES][100], dates[MAX_ENTRIES][20], hexes[MAX_ENTRIES][MAX_TEXT * 2];
    int count = load_entries(username, titles, dates, hexes);
    print_entry_list(titles, dates, count);
    if (count == 0) return;

    printf("\nChoose entry number to delete: ");
    int choice;
    scanf("%d", &choice);
    getchar();
    if (choice < 1 || choice > count) {
        printf("Invalid choice.\n");
        return;
    }
    int idx = choice - 1;

    /* Shift every later entry one slot back, overwriting the deleted one */
    for (int i = idx; i < count - 1; i++) {
        strcpy(titles[i], titles[i + 1]);
        strcpy(dates[i], dates[i + 1]);
        strcpy(hexes[i], hexes[i + 1]);
    }
    count--;

    save_all_entries(username, titles, dates, hexes, count);
    printf("Entry deleted.\n");
}

/* Titles/dates are stored unencrypted, so searching doesn't need a key */
void search_entries(const char *username) {
    char titles[MAX_ENTRIES][100], dates[MAX_ENTRIES][20], hexes[MAX_ENTRIES][MAX_TEXT * 2];
    int count = load_entries(username, titles, dates, hexes);
    if (count == 0) {
        printf("No entries yet.\n");
        return;
    }

    char keyword[100];
    printf("Search title or date (e.g. a word, or 2026-10-02): ");
    fgets(keyword, sizeof(keyword), stdin);
    keyword[strcspn(keyword, "\n")] = 0;

    printf("\n--- Search Results ---\n");
    int found = 0;
    for (int i = 0; i < count; i++) {
        if (strstr(titles[i], keyword) || strstr(dates[i], keyword)) {
            printf("%d) %s  (%s)\n", i + 1, titles[i], dates[i]);
            found++;
        }
    }
    if (!found) printf("No matching entries found.\n");
}

/* ============================================================
   MENUS
   ============================================================ */

void user_menu(const char *username) {
    int choice;
    while (1) {
        printf("\n=== Logged in as: %s ===\n", username);
        printf("1) Add new entry\n");
        printf("2) View / decrypt an entry\n");
        printf("3) Edit an entry\n");
        printf("4) Delete an entry\n");
        printf("5) Search entries\n");
        printf("6) Logout\n");
        printf("Choose an option: ");

        if (scanf("%d", &choice) != 1) {
            while (getchar() != '\n'); /* clear bad input */
            continue;
        }
        getchar(); /* consume leftover newline before any fgets() calls */

        switch (choice) {
            case 1: add_entry(username); break;
            case 2: view_entry(username); break;
            case 3: edit_entry(username); break;
            case 4: delete_entry(username); break;
            case 5: search_entries(username); break;
            case 6: printf("Logged out.\n"); return;
            default: printf("Invalid option.\n");
        }
    }
}

int main() {
    int choice;
    char username[100];

    printf("======================================\n");
    printf("     CIPHER DIARY v2 (Final Year)\n");
    printf("======================================\n");

    while (1) {
        printf("\n1) Register\n");
        printf("2) Login\n");
        printf("3) Exit\n");
        printf("Choose an option: ");

        if (scanf("%d", &choice) != 1) {
            while (getchar() != '\n');
            continue;
        }
        getchar();

        switch (choice) {
            case 1:
                register_user();
                break;
            case 2:
                if (login_user(username)) {
                    user_menu(username);
                }
                break;
            case 3:
                printf("Goodbye!\n");
                return 0;
            default:
                printf("Invalid option.\n");
        }
    }

    return 0;
}