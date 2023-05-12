#include "common.h"

BIO *bioError = 0;
static char *pass;

/**
 * TODO function declaration in header slog.h, inconsistent
 *
 * hexdecimalArray is prepared by caller, size * 2 + 1 at least
 * flag 0, lower case without spaces
 * flag 1, upper case without spaces
 * flag 2, lower case with spaces
 * flag 4, upper case with spaces
 */

void dumpBuffer (const int line, const char *fileName, const char *functionName,
        const int length, const char *bufferName, const char *buffer, int flags) {

    if (length <= 0 || buffer == 0) {
//        slog_debug (7, "%lu %s, buffer %s is null, or length is invalid, %d", pthread_self(), __FUNCTION__,
  //              bufferName,
    //            length
      //          );
        return;
    }

    // We only prints up to 300 bytes
    int size = 1024;
    char hexdecimalArray[size];
    int i = 0; // points to the shorter buffer
    // two hex decimals and a space
    int unitSize = 0;
    while (i < length && i < size / 3 - 1) {

        // be unsigned char
        unsigned char oneChar = (unsigned char) buffer[i];

        // The right shift masks off the high part which is the first hex character 
        // and the 0x0F mask masks off the low part to get the second hex digit.
        // 2 and 3 is the unit size
        switch (flags) {

            case 0:
                unitSize = 2;
                hexdecimalArray[i * unitSize] = "0123456789abcdef"[(oneChar >> 4) & 0x0F];
                hexdecimalArray[i * unitSize + 1] = "0123456789abcdef"[oneChar & 0x0F];
                break;

            case 1:
                unitSize = 2;
                hexdecimalArray[i * unitSize] = "0123456789ABCDEF"[(oneChar >> 4) & 0x0F];
                hexdecimalArray[i * unitSize + 1] = "0123456789ABCDEF"[oneChar & 0x0F];
                break;

            case 2:
                unitSize = 3;
                hexdecimalArray[i * unitSize] = "0123456789abcdef"[(oneChar >> 4) & 0x0F];
                hexdecimalArray[i * unitSize + 1] = "0123456789abcdef"[oneChar & 0x0F];
                hexdecimalArray[i * unitSize + 2] = ' ';
                break;

            case 3:
            default:
                unitSize = 3;
                hexdecimalArray[i * unitSize] = "0123456789ABCDEF"[(oneChar >> 4) & 0x0F];
                hexdecimalArray[i * unitSize + 1] = "0123456789ABCDEF"[oneChar & 0x0F];
                hexdecimalArray[i * unitSize + 2] = ' ';
                break;
        }

        i ++;
    }

    if (unitSize == 2) {
        hexdecimalArray[i * unitSize] = '\0';
    }
    else { // remove space
        hexdecimalArray[i * unitSize - 1] = '\0';
    }

    slog_trace ("%d, %s, %s, length: %d, %s: %s", line, fileName, functionName,
            length,
            bufferName,
            hexdecimalArray
            );

    return;
}


/**
 *
 */
void sigpipe_handle (int x) {
}


/**
 *
 */
static int passwordCb (char *buf, int num, int rwflg, void *userdata) {
    if (num < strlen (pass) + 1) {
        return 0;
    }

    slog_trace ("%s, password: %s", __FUNCTION__, 
           pass 
           );
    strcpy (buf, pass);
    return (strlen (pass));
}


/**
 *
 */
int errExit (char *string) {
    fprintf (stderr, "%lu %d %s %s, %s", pthread_self(), __LINE__, __FILE__, __FUNCTION__, string);
    exit (0);
}


// SSL errors and exit
int berrExit (char *string) {

    BIO_printf (bioError, "%s\n", string);
    ERR_print_errors (bioError);
    exit (0);
}


/**
 *
 */
SSL_CTX *initializeCtx (X509 *cert, RSA *rsa) {

    if (!bioError) {

        // global system initialization
        SSL_library_init();
        SSL_load_error_strings();

        // An error write context
        bioError = BIO_new_fp (stderr, BIO_NOCLOSE);
    }

    // set up a signal handler
    signal (SIGPIPE, sigpipe_handle);

    // Create our context
    // https://www.openssl.org/docs/man1.1.0/man3/TLS_method.html
    const SSL_METHOD *method = TLS_method();
    slog_trace ("%s, TLS_method", __FUNCTION__);

    SSL_CTX *ctx = SSL_CTX_new (method);
    if (ctx == NULL) {
        slog_trace ("%s, init SSL CTX failed", __FUNCTION__);
        berrExit ("init SSL CTX failed\n");
    }

    // new code use cert object
    // No any book mention these functions
    SSL_CTX_use_certificate (ctx, cert);
    
    // Cannot use this function, 
    // It needs EVP_PKEY *pkey
    // SSL_CTX_use_PrivateKey (ctx, rsa);
    SSL_CTX_use_RSAPrivateKey (ctx, rsa);

    // TODO
    // This is introduced in the book Network Seurity with Openssl, p130
    // Not in the book SSL and TLS Designing and Building System Systems
    // SSL_VERIFY_PEER for mutual authentication
    SSL_CTX_set_verify (ctx, SSL_VERIFY_NONE, NULL);

    /*
    // Load our key and certificate
    printf ("%lu %d %s %s, password: %s, keyfile: %s\n", pthread_self(), __LINE__, __FILE__, __FUNCTION__, 
           pass,
           keyfile
           );
    if (!(SSL_CTX_use_certificate_file (ctx, keyfile, SSL_FILETYPE_PEM))) {
        berrExit ("Couldn't read certificate file");
    }

    pass = password;
    SSL_CTX_set_default_passwd_cb (ctx, password_cb);
    if (!(SSL_CTX_use_PrivateKey_file (ctx, keyfile, SSL_FILETYPE_PEM))) {
        berrExit ("Couldn't read key file");
    }

    // Load randomness
    if (!(RAND_load_file (RANDOM, 1024 * 1024, -1))) {
        berrExit ("Coundn't load randomness");
    }
    */

    // Load the CAs we trust, for client, it is the server's certificates
    if (!(SSL_CTX_load_verify_locations (ctx, CA_LIST_TRUSTED, 0))) {
        berrExit ("Coundn't read CA list");
    }
    SSL_CTX_set_verify_depth (ctx, 1);

    slog_trace ("%s, end", __FUNCTION__);
    return ctx;
}

void destoryCtx (SSL_CTX * ctx) {
    SSL_CTX_free (ctx);
    slog_trace ("%s, end", __FUNCTION__);
    return;
}

