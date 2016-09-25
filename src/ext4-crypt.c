#if !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <getopt.h>

#include "ext4-crypt.h"

static
void usage(const char *program)
{
    fprintf(stderr, "Usage: %s [options] <command> [args...]\n", program);
    fprintf(stderr, "Helper tool to use ext4 encrypted directories.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Getting container information\n");
    fprintf(stderr, "  %s status <directory>\n", program);
    fprintf(stderr, "\n");
    fprintf(stderr, "Creating a new encrypted container:\n");
    fprintf(stderr, "  %s create <directory>\n", program);
    fprintf(stderr, "\n");
    fprintf(stderr, "Attaching to an existing encrypted container:\n");
    fprintf(stderr, "  %s attach <directory>\n", program);
    fprintf(stderr, "\n");
    fprintf(stderr, "Detaching from an encrypted container:\n");
    fprintf(stderr, "  %s detach <directory>\n", program);
    fprintf(stderr, "\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -p <LENGTH>:     Filename padding length (default is 4).\n");
    fprintf(stderr, "  -d <DESC>:       Key descriptor (up to 8 characters).\n");
    fprintf(stderr, "  -v:              Verbose output.\n");
}

static
bool is_valid_padding(unsigned padding)
{
    return ( padding == 4 || padding == 8 || padding == 16 || padding == 32 );
}

int main(int argc, char *argv[])
{
    const char *program = basename(argv[0]);
    int c, opt_index;
    size_t desc_len;
    struct ext4_crypt_options opts = {
        .verbose = false,
        .contents_cipher = "aes-256-xts",
        .filename_cipher = "aes-256-cts",
        .filename_padding = 4,
        .key_descriptor = { 0 },
        .requires_descriptor = true,
    };

    while ( true ) {
        static struct option long_options[] = {
            { "help",         no_argument,        0, 'h' },
            { "verbose",      no_argument,        0, 'v' },
            { "name-padding", required_argument,  0, 'p' },
            { "key-desc",     required_argument,  0, 'd' },
            { 0, 0, 0, 0 },
        };

        c = getopt_long(argc, argv, "hvp:d:", long_options, &opt_index);
        if ( c == -1 )
            break;

        switch ( c ) {
            case 'h':
                usage(program);
                return EXIT_SUCCESS;

            case 'v':
                opts.verbose = true;
                break;

            case 'p':
                opts.filename_padding = atoi(optarg); 
                if ( !is_valid_padding(opts.filename_padding) ) {
                    fprintf(stderr, "Invalid filename padding length: must be 4, 8, 16 or 32\n");
                    return EXIT_FAILURE;
                }
                break;

            case 'd':
                desc_len = strlen(optarg);
                if ( desc_len == 0 || desc_len > sizeof(opts.key_descriptor) ) {
                    fprintf(stderr, "Invalid descriptor %s: must be between 1 and 8 characters.", optarg);
                    return EXIT_FAILURE;
                }

                memcpy(opts.key_descriptor, optarg, desc_len);
                opts.requires_descriptor = false;
                break;

            default:
                usage(program);
                return EXIT_FAILURE;
        }
    }

    if ( optind + 1 >= argc ) {
        usage(program);
        return EXIT_FAILURE;
    }

    int status = 0;
    const char *command = argv[optind];
    const char *dir_path = argv[optind + 1];

    if ( strcmp(command, "help") == 0 ) {
        usage(program);
    }
    else if ( strcmp(command, "status") == 0 ) {
        status = container_status(dir_path);
    }
    else if ( strcmp(command, "create") == 0 ) {
        status = container_create(dir_path, opts);
    }
    else if ( strcmp(command, "attach") == 0 ) {
        status = container_attach(dir_path, opts);
    }
    else if ( strcmp(command, "detach") == 0 ) {
        status = container_detach(dir_path, opts);
    }
    else {
        fprintf(stderr, "Error: unrecognized command %s\n", command);
        usage(program);
        status = -1;
    }

    return (status == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
