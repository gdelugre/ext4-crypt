# ext4-crypt

Linux kernel 4.1 introduced native encryption for the ext4 filesystem.

This is a userspace tool to manage encrypted ext4 directories.

**Warning**: this kernel feature is very unstable and experimental at the moment. I managed to crash my kernel (4.1.2) a few times very easily just by playing with it.

## Usage

### Encrypting a new directory

The target directory must be empty.

```console
$ mkdir vault
$ ext4-crypt create vault
Enter passphrase:
Confirm passphrase:
vault: Encryption policy is now set.

$ ext4-crypt status vault
Policy version:   0
Filename cipher:  aes-256-cts
Contents cipher:  aes-256-xts
Filename padding: 4
Key descriptor:   qC6PCZsF
Key serial:       351198062
```

### Unlocking an encrypted directory

```console
$ ls vault
FTRsD7y2dUyXl6e8omKYbB  IdLqPffZBKSebTeh6hZI7C  tReYAc2tKyIOHSIcaSV2DB

$ ext4-crypt attach vault
Enter passphrase: 
Confirm passphrase: 

$ ls vault
fstab  passwd  services
```

## Install

```sh
cmake .
make
sudo make install
```

Distribution packages could be provided later if deemed useful.

## Requirements

Linux kernel 4.1+ with support for ``CONFIG_EXT4_ENCRYPTION``.

## Limitations

### There is **no key verification** !

So basically, any passphrase you provide will be accepted, but you'll get junk
if you provide the wrong key.  This is currently a limitation of the kernel
implementation.

### Cannot choose cipher

Cipher is hardcoded to be AES-256-XTS for data and AES-256-CTS for filenames.
More ciphers will probably be available in future kernel versions.

### You cannot permanently decrypt a directory

The encryption policy is stored at the inode level and cannot be removed from
userspace. You'll need to provide the right key and copy the data to another
directory if you want to remove the encryption.

### Plaintext filenames steal appear after detaching the key

Yep, that also seems to be a kernel bug... 

## Dependencies

- libkeyutils
- [libscrypt](https://github.com/technion/libscrypt)
