#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <linux/random.h>
#include <time.h>
#include <keyutils.h>
#include <termios.h>

#include "ext4-crypt.h"

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
void zero_key(char *key, size_t key_sz)
{
    void *(* volatile memset_s)(void *s, int c, size_t n) = memset;
    memset_s(key, 0, key_sz); 
}

//
// Reads passphrase from terminal input.
//
static
size_t read_key(const char *prompt, char *key, size_t n)
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
// Generates a random ext4 key descriptor.
//
void generate_random_key_descriptor(key_desc_t *key_desc)
{
    const char key_charset[] = { 
        'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 
        'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'z', 'y', 'z',
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 
        'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'Z', 'Y', 'Z',
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9'
    };

    srandom(time(NULL));
    for ( size_t i = 0; i < sizeof(*key_desc); i++ ) {
        (*key_desc)[i] = key_charset[ random() % sizeof(key_charset) ];
    }
}

//
// Lookups a key in the user session keyring from an ext4 key descriptor.
// Returns the key serial number in _serial_.
//
int find_key_by_descriptor(key_desc_t *key_desc, long *serial)
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
// Requests a key to be attached to the specified descriptor.
//
int request_key_for_descriptor(key_desc_t *key_desc)
{
    full_key_desc_t full_key_descriptor;
    build_full_key_descriptor(key_desc, &full_key_descriptor);

    key_serial_t serial = request_key(EXT4_ENCRYPTION_KEY_TYPE,
                                      full_key_descriptor,
                                      NULL,
                                      KEY_SPEC_USER_SESSION_KEYRING);

    // Descriptor key has already been found.
    if ( serial != -1 )
        return 0;

    char encryption_key[EXT4_MAX_KEY_SIZE] = { 0 };
    read_key("Enter passphrase: ", encryption_key, sizeof(encryption_key));

    // TODO: add key to keyring

    zero_key(encryption_key, sizeof(encryption_key));
    return 0;
}
