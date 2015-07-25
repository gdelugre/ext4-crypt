#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <linux/random.h>
#include <time.h>
#include <keyutils.h>
#include <libscrypt.h>
#include <termios.h>
#include <errno.h>

#include "ext4-crypt.h"

//
// Derives passphrase into an ext4 encryption key.
//
static
int derive_passphrase_to_key(char *pass, size_t pass_sz, struct ext4_encryption_key *key)
{
    const unsigned char salt[] = "ext4";

    int ret = libscrypt_scrypt((uint8_t *) pass, pass_sz, 
                               salt, sizeof(salt) - 1, 
                               SCRYPT_N, SCRYPT_r, SCRYPT_p, 
                               (uint8_t *) key->raw, key->size);

    if ( ret != 0 ) {
        fprintf(stderr, "scrypt failed: cannot derive passphrase\n");
        return -1;
    }

    return 0;
}

//
// Converts an ext4 key descriptor to a keyring descriptor.
//
static
void build_full_key_descriptor(key_desc_t *key_desc, full_key_desc_t *full_key_desc)
{
    strcpy(*full_key_desc, EXT4_KEY_DESC_PREFIX);

    for ( size_t i = 0; i < sizeof(*key_desc); i++ ) {
        sprintf(*full_key_desc + EXT4_KEY_DESC_PREFIX_SIZE + i * 2, "%02x", (*key_desc)[i]);
    }
}

// Fill key buffer with zeros.
static
void zero_key(void *key, size_t key_sz)
{
    void *(* volatile memset_s)(void *s, int c, size_t n) = memset;
    memset_s(key, 0, key_sz); 
}

//
// Reads passphrase from terminal input.
//
static
size_t read_passphrase(const char *prompt, char *key, size_t n)
{
    struct termios old, new;
    size_t key_sz = 0;

    fprintf(stderr, "%s", prompt);
    fflush(stderr);

    if ( tcgetattr(fileno(stdin), &old) != 0 )
        return -1;

    /* Disable echo. */
    new = old;
    new.c_lflag &= ~ECHO;
    if ( tcsetattr(fileno(stdin), TCSAFLUSH, &new) != 0 )
        return -1;

    if ( fgets(key, n, stdin) ) {
        key_sz = strlen(key);
    }

    if ( key_sz > 0 && key[key_sz - 1] == '\n' ) {
        key[--key_sz] = '\0';
    }

    /* Restore echo. */
    tcsetattr(fileno(stdin), TCSAFLUSH, &old);

    fprintf(stderr, "\n");
    return key_sz;
}

//
// Initializes state of libc PRNG.
//
static
void init_random()
{
    unsigned int seed;

#if defined(SYS_getrandom)
    syscall(SYS_getrandom, &seed, sizeof(seed), GRND_NONBLOCK);
#else
    int fd = open("/dev/urandom", O_RDONLY);
    if ( fd == -1 ) {
        fprintf(stderr, "Cannot open /dev/urandom: %s\n", strerror(errno));
        abort();
    }

    if ( read(fd, &seed, sizeof(seed)) != sizeof(seed) ) {
        fprintf(stderr, "Cannot read /dev/urandom: %s\n", strerror(errno));
        abort();
    }

    close(fd);
#endif

    srandom(seed);
}

//
// Generates a random name identifier out of a predefined charset.
//
void generate_random_name(char *name, size_t length)
{
    const char key_charset[] = { 
        'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 
        'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'z', 'y', 'z',
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 
        'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'Z', 'Y', 'Z',
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9'
    };

    init_random();
    for ( size_t i = 0; i < length; i++ ) {
        name[i] = key_charset[ random() % sizeof(key_charset) ];
    }
}

//
// Lookups a key in the user session keyring from an ext4 key descriptor.
// Returns the key serial number in _serial_.
//
int find_key_by_descriptor(key_desc_t *key_desc, key_serial_t *serial)
{
    full_key_desc_t full_key_descriptor;
    build_full_key_descriptor(key_desc, &full_key_descriptor);

    long key_serial = keyctl_search(KEY_SPEC_USER_SESSION_KEYRING,
                                    EXT4_ENCRYPTION_KEY_TYPE,
                                    full_key_descriptor,
                                    0);
    if ( key_serial != -1 ) {
        *serial = key_serial;
        return 0;
    }

    return -1;
}

//
// Removes a key given its serial and the keyring it belongs to.
//
int remove_key_for_descriptor(key_desc_t *key_desc)
{
    key_serial_t key_serial;
    if ( find_key_by_descriptor(key_desc, &key_serial) < 0 )
        return -1;

    if ( keyctl_unlink(key_serial, KEY_SPEC_USER_SESSION_KEYRING) == -1 ) {
        fprintf(stderr, "Cannot remove encryption key: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

//
// Requests a key to be attached to the specified descriptor.
//
int request_key_for_descriptor(key_desc_t *key_desc, struct ext4_crypt_options opts, bool confirm)
{
    int retries = 5;
    char passphrase[EXT4_MAX_PASSPHRASE_SZ];
    char confirm_passphrase[sizeof(passphrase)];
    size_t pass_sz;
    full_key_desc_t full_key_descriptor;
    build_full_key_descriptor(key_desc, &full_key_descriptor);

    while ( --retries >= 0 ) {
        pass_sz = read_passphrase("Enter passphrase: ", passphrase, sizeof(passphrase));
        if ( pass_sz == 0 ) {
            fprintf(stderr, "Passphrase cannot be empty.\n");
            continue;
        }

        if ( !confirm )
            break;

        read_passphrase("Confirm passphrase: ", confirm_passphrase, sizeof(confirm_passphrase));
        if ( strcmp(passphrase, confirm_passphrase) == 0 )
            break;

        fprintf(stderr, "Password mismatch.\n");
    }

    if ( retries < 0 ) {
        fprintf(stderr, "Cannot read passphrase.\n");
        return -1;
    }

    struct ext4_encryption_key master_key = {
        .mode = 0,
        .raw = { 0 },
        .size = cipher_key_size(opts.contents_cipher),
    };
    if ( derive_passphrase_to_key(passphrase, pass_sz, &master_key) < 0 )
        return -1;

    key_serial_t serial = add_key(EXT4_ENCRYPTION_KEY_TYPE,
                                  full_key_descriptor,
                                  &master_key,
                                  sizeof(master_key),
                                  KEY_SPEC_USER_SESSION_KEYRING
                                 );

    if ( serial == -1 ) {
        fprintf(stderr, "Cannot add key to keyring: %s\n", strerror(errno));
        return -1;
    }

    zero_key(passphrase, sizeof(passphrase));
    zero_key(confirm_passphrase, sizeof(confirm_passphrase));
    zero_key(&master_key, sizeof(master_key));
    return 0;
}
