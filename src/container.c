#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/fcntl.h>
#include <linux/magic.h>
#include <sys/vfs.h>
#include <asm-generic/ioctl.h>
#include <stropts.h>
#include <assert.h>
#include <errno.h>

#include "ext4-crypt.h"

//
// Checks the given file path is mounted on a ext4 filesystem.
//
static
bool is_ext4_filesystem(const char *path)
{
    struct statfs fs;

    if ( statfs(path, &fs) != 0 ) {
        fprintf(stderr, "Cannot get filesystem information for %s: %s\n", path, strerror(errno));
        return false;
    }

    return (fs.f_type == EXT4_SUPER_MAGIC);
}

//
// Opens an existing file on an ext4 filesystem.
// Returns a read-only file descriptor.
//
static
int open_ext4_path(const char *path, int flags)
{
    if ( !is_ext4_filesystem(path) ) {
        fprintf(stderr, "Error: %s does not belong to an ext4 filesystem.\n", path);
        return -1;
    }

    int open_flags = O_RDONLY | O_NONBLOCK | flags;
    int fd = open(path, open_flags);
    if ( fd == -1 ) {
        if ( errno == ENOTDIR )
            fprintf(stderr, "Invalid argument: %s is not a directory\n", path);
        else
            fprintf(stderr, "Cannot open %s: %s\n", path, strerror(errno));

        return -1;
    }

    return fd;
}

//
// Opens an existing directory on an ext4 filesystem.
// Returns a file descriptor of the directory.
//
static
int open_ext4_directory(const char *dir_path)
{
    return open_ext4_path(dir_path, O_DIRECTORY);
}

//
// Queries the kernel for inode encryption policy.
//
static
int get_ext4_encryption_policy(int dirfd, struct ext4_encryption_policy *policy, bool *has_policy)
{
    if ( ioctl(dirfd, EXT4_IOC_GET_ENCRYPTION_POLICY, policy) < 0 ) {
        switch ( errno ) {
            case ENOENT:
                *has_policy = false;
                return 0;

            case ENOTSUP:
                fprintf(stderr, "This filesystem does not support encryption.\n");
                fprintf(stderr, "Please ensure your kernel has support for CONFIG_EXT4_ENCRYPTION.\n");
                return -1;

            default:
                fprintf(stderr, "Cannot get ext4 encryption policy: %s\n", strerror(errno));
                return -1;
        }
    }

    *has_policy = true;
    return 0;
}

//
// Applies ext4 specified encryption policy to directory.
//
static
int set_ext4_encryption_policy(int dirfd, struct ext4_encryption_policy *policy)
{
    if ( ioctl(dirfd, EXT4_IOC_SET_ENCRYPTION_POLICY, policy) < 0 ) {
        switch ( errno ) {
            case ENOTSUP:
                fprintf(stderr, "This filesystem does not support encryption.\n");
                fprintf(stderr, "Please ensure your kernel has support for CONFIG_EXT4_ENCRYPTION.\n");
                return -1;

            case EINVAL:
                fprintf(stderr, "Encryption parameters do not match with already previous ones.\n");
                return -1;

            case ENOTEMPTY:
                fprintf(stderr, "Cannot create encrypted container: directory must be empty.\n");
                return -1;

            default:
                fprintf(stderr, "Cannot set ext4 encryption policy: %s\n", strerror(errno));
                return -1;
        }
    }

    return 0;
}

//
// Setups a new encryption policy for the specified directory.
//
static
int setup_ext4_encryption(int dirfd, struct ext4_crypt_options opts) 
{
    struct ext4_encryption_policy policy;    

    // Current policy version.
    policy.version = 0;

    policy.contents_encryption_mode = cipher_string_to_mode(opts.contents_cipher);
    policy.filenames_encryption_mode = cipher_string_to_mode(opts.filename_cipher);
    policy.flags = padding_length_to_flags(opts.filename_padding);

    if ( opts.requires_descriptor )
        generate_random_name(opts.key_descriptor, sizeof(opts.key_descriptor));

    memcpy(policy.master_key_descriptor, opts.key_descriptor, sizeof(policy.master_key_descriptor));

    VERBOSE_PRINT(opts, "Configuring ext4 encryption policy:");
    VERBOSE_PRINT(opts, "  version:          %d", policy.version);
    VERBOSE_PRINT(opts, "  contents cipher:  %s", opts.contents_cipher);
    VERBOSE_PRINT(opts, "  filename cipher:  %s", opts.filename_cipher);
    VERBOSE_PRINT(opts, "  filename padding: %d", opts.filename_padding);
    VERBOSE_PRINT(opts, "  key descriptor:   %s", opts.key_descriptor);
    
    return set_ext4_encryption_policy(dirfd, &policy);
}

//
// Prints information about directory container.
//
int container_status(const char *dir_path)
{
    int dirfd = open_ext4_directory(dir_path);
    if ( dirfd == -1 )
        return -1;

    struct ext4_encryption_policy policy;
    bool has_policy;

    if ( get_ext4_encryption_policy(dirfd, &policy, &has_policy) < 0 )
        return -1;

    if ( !has_policy )
        printf("%s: Regular directory\n", dir_path);
    else {

        printf("%s: Encrypted directory\n", dir_path);
        printf("Policy version:   %d\n", policy.version);
        printf("Filename cipher:  %s\n", cipher_mode_to_string(policy.filenames_encryption_mode));
        printf("Contents cipher:  %s\n", cipher_mode_to_string(policy.contents_encryption_mode));
        printf("Filename padding: %d\n", flags_to_padding_length(policy.flags));
        printf("Key descriptor:   %.8s\n", policy.master_key_descriptor);
        
        key_serial_t key_serial;
        if ( find_key_by_descriptor(&policy.master_key_descriptor, &key_serial) == -1 )
            printf("Key serial:       not found\n");
        else
            printf("Key serial:       %d\n", key_serial);
    }

    return 0;
}

//
// XXX: There seems to be a bug when the block if the block is unmounted but no encrypted inode was created.
// We create here a dummy inode file and unlinks it immediately.
//
static
int create_dummy_inode(int dirfd)
{
    char dummy_name[16 + 1];

    generate_random_name(dummy_name, sizeof(dummy_name) - 1);
    dummy_name[sizeof(dummy_name) - 1] = '\0';

    int fd = openat(dirfd, dummy_name, O_NONBLOCK|O_CREAT|O_TRUNC|O_RDWR, S_IRUSR|S_IWUSR);
    if ( fd == -1 ) {
        fprintf(stderr, "Cannot create inode in directory: %s\n", strerror(errno));
        return -1;
    }

    if ( unlinkat(dirfd, dummy_name, 0) != 0 ) {
        fprintf(stderr, "Cannot unlink inode in directory: %s\n", strerror(errno));
        return -1;
    }

    close(fd);
    return 0;
}

//
// Creates a new encrypted container at directory _dir_path_.
//
int container_create(const char *dir_path, struct ext4_crypt_options opts)
{
    int dirfd = open_ext4_directory(dir_path);
    if ( dirfd == -1 )
        return -1;

    struct ext4_encryption_policy policy;
    bool has_policy;

    // We first check the directory is not already encrypted.
    if ( get_ext4_encryption_policy(dirfd, &policy, &has_policy) < 0 )
        return -1;
    
    if ( has_policy ) {
        fprintf(stderr, "Cannot create encrypted container at %s: directory is already encrypted.\n", dir_path);
        return -1;
    }

    // Creates the encryption policy.
    if ( setup_ext4_encryption(dirfd, opts) < 0 )
        return -1;

    // Checks the encryption policy was successfully created.
    if ( get_ext4_encryption_policy(dirfd, &policy, &has_policy) < 0 )
        return -1;
    
    if ( !has_policy ) {
        fprintf(stderr, "Encryption policy creation failed for %s.\n", dir_path);
        return -1;
    }

    // Attaches a key to the directory.
    if ( request_key_for_descriptor(&policy.master_key_descriptor, opts, true) < 0 )
        return -1;

    // XXX: must write a file to the directory...
    // The directory is left in an inconsistent state if the superblock is unmounted before any inode is created.
    if ( create_dummy_inode(dirfd) < 0 )
        return -1;

    printf("%s: Encryption policy is now set.\n", dir_path);
    close(dirfd);
    return 0;
}

//
// Attaches a key to an encrypted directory.
//
int container_attach(const char *dir_path, struct ext4_crypt_options opts)
{
    int dirfd = open_ext4_directory(dir_path);
    if ( dirfd == -1 )
        return -1;
    
    struct ext4_encryption_policy policy;    
    bool has_policy;

    // We check that an encryption policy has already been defined for this directory.
    if ( get_ext4_encryption_policy(dirfd, &policy, &has_policy) < 0 )
        return -1;

    if ( !has_policy ) {
        fprintf(stderr, "Cannot attach key to directory %s: not an encrypted directory.\n", dir_path);
        return -1;
    }

    if ( request_key_for_descriptor(&policy.master_key_descriptor, opts, false) < 0 )
        return -1;

    close(dirfd);
    return 0;
}

int container_detach(const char *dir_path, struct ext4_crypt_options opts)
{
    (void) opts;

    int dirfd = open_ext4_directory(dir_path);
    if ( dirfd == -1 )
        return -1;
    
    struct ext4_encryption_policy policy;    
    bool has_policy;

    // We check that an encryption policy has already been defined for this directory.
    if ( get_ext4_encryption_policy(dirfd, &policy, &has_policy) < 0 )
        return -1;

    if ( !has_policy ) {
        fprintf(stderr, "%s has no active encryption policy.\n", dir_path);
        return -1;
    }

    if ( remove_key_for_descriptor(&policy.master_key_descriptor) < 0 )
        return -1;
    
    printf("Encryption key detached from %s.\n", dir_path);
    close(dirfd);
    return 0;
}
