#include "common.h"
#include "client.h"
#include "readWrite.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

// Added for chmod(), otherwise, C warning: implicit declaration of function ‘chmod’
#include <sys/stat.h>
#include <pthread.h>

#include <openssl/conf.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/pem.h>

int DEBUG = 0;

// All are case sensitive
#define GLOBAL_VARIABLE "HOME"
#define GLOBAL_NUMBER "RANDFILE"

#define ENTRY_COUNT 6
struct entry {
    char *key;
    char *value;
};

// Searching path is Section req, 
// then find distinguished_name = phone_distinguished_name, 
// then go to Section phone_distinguished_name, and iterate all key-values pairs
#define PARAMS "req"
#define SEC_NAME "distinguished_name"  

#define CA_FILE "certificates/ca.crt"
#define CA_KEY "certificates/ca.key"

// For debugging purposes, we can generate these 4 files, verify and then read from them
#define PUBLIC_KEY_FILE "certificates/ucs.generated.pub"
#define PRIVATE_KEY_FILE "certificates/ucs.generated.key"
#define REQ_FILE "certificates/ucs.generated.req"
#define CERT_FILE "certificates/ucs.generated.crt"

#define DAYS_TILL_EXPIRE 365
#define EXPIRE_SECS (60*60*24*DAYS_TILL_EXPIRE)

#define EXT_COUNT 5

typedef struct ArgsStruct {
    //Or whatever information that you need
    char *configurationFile;
    char *host;
    int iterations;
    int threadId;
    int range; // per thread
} ArgsStruct;


void handleError (const char *file, int lineno, const char *msg) {
    fprintf (stderr, "** %s:%i %s\n", file, lineno, msg);
    ERR_print_errors_fp (stderr);
    exit (-1);
}

#define int_error(msg) handleError(__FILE__, __LINE__, msg)

int seedPrng (int bytes) {
    /*
    // if (!RAND_load_file ("/dev/random", -1)) {
    if (!RAND_load_file ("/dev/random", bytes)) {
    return 0;
    }
    */
    return 1;
}


/**
 * Read from txt file to conf
 */
int readConfiguration (CONF **conf, char *configurationFile) {

    int i;
    long i_val, err = 0;
    char *key, *s_val;
    STACK_OF (CONF_VALUE) * sec;
    CONF_VALUE *item;

    *conf = NCONF_new (NCONF_default());
    if (!NCONF_load (*conf, configurationFile, &err)) {
        if (err == 0) {
            fprintf (stderr, "Error opening configuration file: %s\n", configurationFile);
            int_error ("Error opening configuration file");
        }
        else {
            fprintf (stderr, "Error in %s on line %li\n", configurationFile, err);
            int_error ("Errors parsing configuration file");
        }
    }

    slog_trace ("Read configuration file from: %s", configurationFile);

    if (!(s_val = NCONF_get_string (*conf, NULL, GLOBAL_VARIABLE))) {
        fprintf (stderr, "Error finding GLOBAL_VARIABLE: \"%s\"\n", GLOBAL_VARIABLE);
        int_error ("Error finding string");
    }
    printf ("%lu %d %s %s, global Sec: Key: %s, Val: %li\n", pthread_self(), __LINE__, __FILE__, __FUNCTION__, GLOBAL_VARIABLE, i_val);

    if (!(err = NCONF_get_number_e (*conf, NULL, GLOBAL_NUMBER, &i_val))) {
        fprintf (stderr, "Error finding GLOBAL_NUMBER: \"%s\"\n", GLOBAL_NUMBER);
        int_error ("Error finding number");
    }
    slog_trace ("%s, global variable, Key: %s, Val: %li\n", __FUNCTION__, GLOBAL_NUMBER, i_val);

    if (!(key = NCONF_get_string (*conf, PARAMS, SEC_NAME))) {
        fprintf (stderr, "Error finding \"%s\" in [%s]\n", SEC_NAME, PARAMS);
        int_error ("Error finding string");
    }
    slog_trace ("%s, Sec: %s, Key: %s, Val: %s\n", __FUNCTION__, PARAMS, SEC_NAME, key);

    if (!(sec = NCONF_get_section (*conf, key))) {
        fprintf (stderr, "Error finding [%s]\n", key);
        int_error ("Error finding string");
    }

    for (i = 0; i < sk_CONF_VALUE_num (sec); i++) {
        item = sk_CONF_VALUE_value (sec, i);
        printf ("%lu %d %s %s, Sec: %s, Key: %s, Val: %s\n", pthread_self(), __LINE__, __FILE__, __FUNCTION__, item->section, item->name, item->value);
    }

    // TODO, not free here, who will free?
    // NCONF_free (*conf);
    return 0;
}


/**
 *
 *  To automatically generate all MACs, serial nos
 *
 *  MAC Address is a 12-digit hexadecimal number (6-Byte binary number), which is mostly represented by Colon-Hexadecimal notation. First 6-digits (say 00:40:96) of MAC Address identifies the manufacturer, called as OUI (Organizational Unique Identifier).
 *
 *  As a recap, remember that the maximum number stored in a 64 bit (8 bytes long) register / variable is 2^64 – 1 = 18446744073709551615 (a 20 digit number).
 *
 *
 */
int changeMac (char* mac, int threadId) {

    // Add mac + delta to make it unique
    unsigned long long macNumber = strtoull (mac, NULL, 16);
    printf ("%lu %d %s %s, base mac: %s, macNumber: %lld\n", pthread_self(), __LINE__, __FILE__, __FUNCTION__, 
            mac, 
            macNumber
           );

    macNumber += threadId;
    sprintf (mac, "%12llX", macNumber);

    printf ("%lu %d %s %s, new mac: %s, \n", pthread_self(), __LINE__, __FILE__, __FUNCTION__, 
            mac
           );

    return 0;
}


/**
 *
 */
int changeCommonName (char* commonName, int threadId) {

    // Add mac + delta to make it unique
    unsigned long long commonNameNumber = strtoull (commonName, NULL, 10);

    if (strlen(commonName) != 9) {
        slog_trace ("%s, bad commonName: %s", __FUNCTION__,
                commonName
                );
        return 1;
    }

    slog_trace ("%s, base commonName: %s, commonNameNumber: %lld", __FUNCTION__,
            commonName, 
            commonNameNumber
            );

    commonNameNumber += threadId;

    // We only need rightmost 9 digits
    sprintf (commonName, "%lld", commonNameNumber);

    slog_trace ("%s, new commonNameNumber: %lld", __FUNCTION__,
            commonNameNumber
            );

    return 0;
}


/**
 *
 *  To automatically generate all MACs, serial no 
 *  read this configuration file and start from here
 */
int assignConfiguration (X509_NAME **subj, CONF *conf, int threadId) {

    int i;
    long i_val, err = 0;
    char *key, *s_val;
    STACK_OF (CONF_VALUE) * sec;
    CONF_VALUE *item;

    if (!(s_val = NCONF_get_string (conf, NULL, GLOBAL_VARIABLE))) {
        slog_trace ("Error finding GLOBAL_VARIABLE: \"%s\"", GLOBAL_VARIABLE);
        int_error ("Error finding string");
    }
    slog_trace ("%s, global Sec: Key: %s, Val: %li\n", __FUNCTION__, GLOBAL_VARIABLE, i_val);

    if (!(err = NCONF_get_number_e (conf, NULL, GLOBAL_NUMBER, &i_val))) {
        fprintf (stderr, "Error finding GLOBAL_NUMBER: \"%s\"\n", GLOBAL_NUMBER);
        int_error ("Error finding number");
    }
    printf ("%lu %d %s %s, global Sec: Key: %s, Val: %li\n", pthread_self(), __LINE__, __FILE__, __FUNCTION__, GLOBAL_VARIABLE, i_val);

    if (!(key = NCONF_get_string (conf, PARAMS, SEC_NAME))) {
        fprintf (stderr, "Error finding \"%s\" in [%s]\n", SEC_NAME, PARAMS);
        int_error ("Error finding string");
    }
    slog_trace ("%s, Sec: %s, Key: %s, Val: %s\n", __FUNCTION__, PARAMS, SEC_NAME, key);

    if (!(sec = NCONF_get_section (conf, key))) {
        fprintf (stderr, "Error finding [%s]\n", key);
        int_error ("Error finding string");
    }

    for (i = 0; i < sk_CONF_VALUE_num (sec); i ++) {
        // Inside the loop
        int nid;
        X509_NAME_ENTRY *x509Entry;

        item = sk_CONF_VALUE_value (sec, i);
        printf ("%lu %d %s %s, Sec: %s, Key: %s, Val: %s\n", pthread_self(), __LINE__, __FILE__, __FUNCTION__, item->section, item->name, item->value);
        if ((nid = OBJ_txt2nid (item->name)) == NID_undef) {
            fprintf (stderr, "Error finding NID for %s\n", item->name);
            int_error ("Error on lookup");
        }

        if ((strcmp (item->name, "stateOrProvinceName") == 0) || (strcmp (item->name, "localityName") == 0)) {

            char mac[13];
            strcpy (mac, item->value);
            changeMac (mac, threadId);

            x509Entry = X509_NAME_ENTRY_create_by_NID (NULL, nid, MBSTRING_ASC, mac, -1);
        }
        else if (strcmp (item->name, "commonName") == 0) {

            char commonName[13];
            strcpy (commonName, item->value);
            changeCommonName (commonName, threadId);

            x509Entry = X509_NAME_ENTRY_create_by_NID (NULL, nid, MBSTRING_ASC, commonName, -1);
            // x509Entry = X509_NAME_ENTRY_create_by_NID (NULL, nid, MBSTRING_ASC, item->value, -1);
        }
        else {
            x509Entry = X509_NAME_ENTRY_create_by_NID (NULL, nid, MBSTRING_ASC, item->value, -1);
        }

        // Defensive check above 3 cases
        if (!x509Entry) {
            int_error ("Error creating Name entry from NID");
        }

        if (X509_NAME_add_entry (*subj, x509Entry, -1, 0) != 1) {
            int_error ("Error adding entry to Name");
        }
    }

    // NCONF_free (*conf);
    return 0;
}


/**
 * 
 * Return 0 is success
 * Other values, failure
 *
 */
int generateKey (RSA **rsa) {

    int ret = 0;
    BIGNUM *bigNumberEngine = NULL;
    BIO	*bp_public = NULL, *bp_private = NULL;

    int bits = 2048;
    unsigned long e = RSA_F4;

    // 1. generate rsa key
    bigNumberEngine = BN_new();
    ret = BN_set_word (bigNumberEngine, e);
    if (ret != 1) {
        goto free_all;
    }

    *rsa = RSA_new();
    ret = RSA_generate_key_ex (*rsa, bits, bigNumberEngine, NULL);
    if (ret != 1) {
        goto free_all;
    }

    // Write to files for debugging purpose
    // openssl rsa -text -noout -in sclient.generated.pub
    // openssl rsa -text -noout -in sclient.generated.key
    // 2. save public key
    if (DEBUG) {
        bp_public = BIO_new_file (PUBLIC_KEY_FILE, "w+");
        ret = PEM_write_bio_RSAPublicKey (bp_public, *rsa);
        if (ret != 1) {
            goto free_all;
        }

        // 3. save private key
        // Remove the existing files if exist
        // otherwise, cause error when write
        unlink (PRIVATE_KEY_FILE);

        // No password now
        bp_private = BIO_new_file (PRIVATE_KEY_FILE, "w+");
        ret = PEM_write_bio_RSAPrivateKey (bp_private, *rsa, NULL, NULL, 0, NULL, NULL);
        if (ret != 1) {
            goto free_all;
        }
    }

    // chmod 400 for PEM_read_PrivateKey() requirements
    chmod (PRIVATE_KEY_FILE, S_IRUSR);
    return 0;

    // 4. free
free_all:

    BIO_free_all (bp_public);
    BIO_free_all (bp_private);
    BN_free (bigNumberEngine);
    RSA_free (*rsa);

    return 1;
}

/**
 * 
 * Return 0 is success
 * Other values, failure
 *
 */
int generatRequests (int threadId, X509_REQ **req, CONF *conf, RSA *rsa) {

    int i;

    X509_NAME *subj;
    EVP_PKEY *pkey;
    FILE *fp;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    seedPrng (1);

    /* 
     // For debugging pruposes
     // first read in the private key
       if (!(fp = fopen (PKEY_FILE, "r"))) {
       int_error ("Error reading private key file");
       }
       if (!(pkey = PEM_read_PrivateKey (fp, NULL, NULL, NULL))) {
       int_error ("Error reading private key in file");
       }
       fclose (fp);
       */

    pkey = EVP_PKEY_new();
    if (!pkey) {
        int_error ("EVP_PKEY_new: failed.");
    }

    int ret = 0;
    BIGNUM *bigNumberEngine = NULL;
    BIO	*bp_public = NULL, *bp_private = NULL;

    int bits = 2048;
    unsigned long e = RSA_F4;

    EVP_PKEY_assign_RSA (pkey, rsa);

    // create a new request and add the key to it
    if (!(*req = X509_REQ_new())) {
        int_error ("Failed to create X509_REQ object");
    }
    X509_REQ_set_pubkey (*req, pkey);

    // assign the subject name
    if (!(subj = X509_NAME_new())) {
        int_error ("Failed to create X509_NAME object");
    }

    assignConfiguration (&subj, conf, threadId);

    if (X509_REQ_set_subject_name (*req, subj) != 1) {
        int_error ("Error adding subject to the request");
    }

    // add an extension for the FQDN we wish to have 
    {
        X509_EXTENSION *ext;
        STACK_OF (X509_EXTENSION) * extlist;
        char *name = "subjectAltName";
        char *value = "DNS:splat.zork.org";

        extlist = sk_X509_EXTENSION_new_null();

        if (!(ext = X509V3_EXT_conf (NULL, NULL, name, value))) {
            int_error ("Error creating subjectAltName extension");
        }

        sk_X509_EXTENSION_push (extlist, ext);

        if (!X509_REQ_add_extensions (*req, extlist)) {
            int_error ("Error adding subjectAltName to the request");
        }
        sk_X509_EXTENSION_pop_free (extlist, X509_EXTENSION_free);
    }

    const EVP_MD *digest;
    // pick the correct digest and sign the request
    if (EVP_PKEY_base_id (pkey) == EVP_PKEY_DSA) {
        digest = EVP_sha1();
    }
    else if (EVP_PKEY_base_id (pkey) == EVP_PKEY_RSA) {
        digest = EVP_sha1();
    }
    else {
        int_error ("Error checking public key for a valid digest");
    }

    if (!(X509_REQ_sign (*req, pkey, digest))) {
        int_error ("Error signing request");
    }

    // To check the file contents
    // openssl req -text -noout -verify -in sclient.generated.req
    if (DEBUG) {
        if (!(fp = fopen (REQ_FILE, "w"))) {
            int_error ("Error writing to request file");
        }
        if (PEM_write_X509_REQ (fp, *req) != 1) {
            int_error ("Error while writing request");
        }
        fclose (fp);
    }

    EVP_PKEY_free (pkey);

    return 0;
}

struct entry ext_ent[EXT_COUNT] = {
    {"basicConstraints", "CA:FALSE"},
    {"nsComment", "\"OpenSSL Generated Certificate\""},
    {"subjectKeyIdentifier", "hash"},
    {"authorityKeyIdentifier", "keyid,issuer:always"},
    {"keyUsage", "nonRepudiation,digitalSignature,keyEncipherment"}
};


/**
 *
 */
int makeCertificate (X509 **cert, X509_REQ *req) {

    int i, subjAltName_pos;
    long serial = 1;
    EVP_PKEY *pkey, *CApkey;
    const EVP_MD *digest;
    // root certificate
    X509 *CAcert;

    X509_NAME *name;
    X509V3_CTX ctx;
    X509_EXTENSION *subjAltName;
    STACK_OF (X509_EXTENSION) * req_exts;
    FILE *fp;
    BIO *out;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    seedPrng (2);

    // open stdout
    if (!(out = BIO_new_fp (stdout, BIO_NOCLOSE))) {
        int_error ("Error creating stdout BIO");
    }

    /*
    // For debugging purpose, we can read from the file
    if (!(fp = fopen (REQ_FILE, "r")))
        int_error ("Error reading request file");
    if (!(req = PEM_read_X509_REQ (fp, NULL, NULL, NULL)))
        int_error ("Error reading request in file");
    fclose (fp);
    */

    // verify signature on the request
    if (!(pkey = X509_REQ_get_pubkey (req))) {
        int_error ("Error getting public key from request");
    }

    if (X509_REQ_verify (req, pkey) != 1) {
        int_error ("Error verifying signature on certificate");
    }

    // read in the CA certificate
    if (!(fp = fopen (CA_FILE, "r"))) {
        int_error ("Error reading CA certificate file from CA_FILE");
        // slog_trace ("%s, Error reading CA certificate file: %s", __FUNCTION__, CA_FILE);
        slog_trace ("Error reading CA certificate file: %s", CA_FILE);
    }

    if (!(CAcert = PEM_read_X509 (fp, NULL, NULL, NULL)))
        int_error ("Error reading CA certificate in file");
    fclose (fp);

    /* read in the CA private key */
    if (!(fp = fopen (CA_KEY, "r")))
        int_error ("Error reading CA private key file");
    if (!(CApkey = PEM_read_PrivateKey (fp, NULL, NULL, "password")))
        int_error ("Error reading CA private key in file");
    fclose (fp);

    /* print out the subject name and subject alt name extension */
    if (!(name = X509_REQ_get_subject_name (req)))
        int_error ("Error getting subject name from request");
    X509_NAME_print (out, name, 0);
    fputc ('\n', stdout);
    if (!(req_exts = X509_REQ_get_extensions (req)))
        int_error ("Error getting the request's extensions");
    subjAltName_pos = X509v3_get_ext_by_NID (req_exts,
            OBJ_sn2nid ("subjectAltName"), -1);
    subjAltName = X509v3_get_ext (req_exts, subjAltName_pos);
    X509V3_EXT_print (out, subjAltName, 0, 0);
    fputc ('\n', stdout);

    /* WE SHOULD NOW ASK WHETHER TO CONTINUE OR NOT */

    /* create new certificate */
    if (!(*cert = X509_new()))
        int_error ("Error creating X509 object");

    /* set version number for the certificate (X509v3) and the serial number */
    if (X509_set_version (*cert, 2L) != 1)
        int_error ("Error settin certificate version");
    ASN1_INTEGER_set (X509_get_serialNumber (*cert), serial++);

    /* set issuer and subject name of the cert from the req and the CA */
    if (!(name = X509_REQ_get_subject_name (req)))
        int_error ("Error getting subject name from request");
    if (X509_set_subject_name (*cert, name) != 1)
        int_error ("Error setting subject name of certificate");
    if (!(name = X509_get_subject_name (CAcert)))
        int_error ("Error getting subject name from CA certificate");
    if (X509_set_issuer_name (*cert, name) != 1)
        int_error ("Error setting issuer name of certificate");

    /* set public key in the certificate */
    if (X509_set_pubkey (*cert, pkey) != 1)
        int_error ("Error setting public key of the certificate");

    /* set duration for the certificate */
    if (!(X509_gmtime_adj (X509_get_notBefore (*cert), 0)))
        int_error ("Error setting beginning time of the certificate");
    if (!(X509_gmtime_adj (X509_get_notAfter (*cert), EXPIRE_SECS)))
        int_error ("Error setting ending time of the certificate");

    /* add x509v3 extensions as specified */
    X509V3_set_ctx (&ctx, CAcert, *cert, NULL, NULL, 0);
    for (i = 0; i < EXT_COUNT; i++) {
        X509_EXTENSION *ext;
        if (!(ext = X509V3_EXT_conf (NULL, &ctx,
                        ext_ent[i].key, ext_ent[i].value)))
        {
            fprintf (stderr, "Error on \"%s = %s\"\n",
                    ext_ent[i].key, ext_ent[i].value);
            int_error ("Error creating X509 extension object");
        }
        if (!X509_add_ext (*cert, ext, -1)) {
            fprintf (stderr, "Error on \"%s = %s\"\n",
                    ext_ent[i].key, ext_ent[i].value);
            int_error ("Error adding X509 extension to certificate");
        }
        X509_EXTENSION_free (ext);
    }

    /* add the subjectAltName in the request to the cert */
    if (!X509_add_ext (*cert, subjAltName, -1))
        int_error ("Error adding subjectAltName to certificate");

    /* sign the certificate with the CA private key */
    if (EVP_PKEY_base_id (CApkey) == EVP_PKEY_DSA)
        // digest = EVP_dss1 ();
        digest = EVP_sha1();
    else if (EVP_PKEY_base_id (CApkey) == EVP_PKEY_RSA)
        digest = EVP_sha1();
    else
        int_error ("Error checking CA private key for a valid digest");
    if (!(X509_sign (*cert, CApkey, digest)))
        int_error ("Error signing certificate");

    // write the completed certificate
    // openssl x509 -text -noout -in sclient.generated.crt
    if (DEBUG) {
        if (!(fp = fopen (CERT_FILE, "w")))
            int_error ("Error writing to certificate file");
        if (PEM_write_X509 (fp, *cert) != 1)
            int_error ("Error while writing certificate");
        fclose (fp);
    }

    return 0;
}


/**
 * One thread uses only one MAC to send
 */
void *workerThread (void *input) {

    ArgsStruct *args = input;

    // 1. read configuration file for commom values
    CONF *conf;
    readConfiguration (&conf, args->configurationFile);

    // 2. 
    RSA *rsa;
    generateKey (&rsa);

    // 3. Generating a request
    X509_REQ *req;
    int threadId = args->threadId;
    slog_trace ("%s, sclient thread: %d", __FUNCTION__, threadId);

    generatRequests (threadId, &req, conf, rsa);

    // 4. Making a certificate
    X509 *cert;
    makeCertificate (&cert, req);

    // 5. Build SSL context
    SSL_CTX *ctx;
    SSL *ssl;
    BIO *sbio;
    int tcpSocketFd;

    ctx = initializeCtx (cert, rsa);

    tcpSocketFd = tcpConnect (args->host);

    ssl = SSL_new (ctx);
    sbio = BIO_new_socket (tcpSocketFd, BIO_NOCLOSE);
    SSL_set_bio (ssl, sbio, sbio);
    if (SSL_connect (ssl) <= 0) {
        berrExit ("SSL connect error");
    }

    checkCertificateChain (ssl, args->host);
    slog_trace ("%s, SSL connect to server with success",  __FUNCTION__);

    // loop inside
    readWrite (args->iterations, ssl, tcpSocketFd);

    destoryCtx (ctx);

    return NULL;
}


void greet() {
    // Get and print slog version 
    printf ("=========================================\n");
    printf ("SLog Version: %s\n", slog_version (0));
    printf ("=========================================\n");
}

/**
 * iteartion 0 is for infinitely loop
 *
 * Total messages sent = iterations * number_of_threads * unique_mac_per_thread
 */ 
int main (int argc, char *argv[]) {

    if (argc < 7) {
        printf ("Error: Usage: s_client configure_file host iterations number_of_threads unique_mac_per_thread DEBUG\n");
        exit (0);
    }

    if (strcmp (argv[6], "DEBUG") == 0) {
        DEBUG = 1;
    }

    // begin of testing slog
    SLogConfig slgCfg;
    int nInteger = 69;
    char sBuffer[12];

    strcpy(sBuffer, "test string");
    uint16_t nLogFlags = SLOG_ERROR | SLOG_NOTAG;

    greet();

    // Initialize slog and allow only error and not tagged output 
    // log file name s_client-2021-01-22.log
    slog_init ("s_client", nLogFlags, 0);

    // Just simple log without anything (color, tag, thread id)
    slog ("Simple message without anything");

    /* Simple log without adding new line character at the end */
    slogwn ("Simple message with our own new line character\n");

    /* Enable all logging flags */
    slog_enable (SLOG_FLAGS_ALL);

    /* Old way logging function with debug tag and disabled new line from argument */
    slog_print (SLOG_DEBUG, 0, "Old way printed debug message with our own new line character\n");

    /* Old way logging function with error tag and enabled new line from argument */
    slog_print (SLOG_ERROR, 1, "Old way printed error message with %s", "auto new line character");

    /* Warning message */
    slog_warn ("Warning message without variable");

    /* Info message with char*/
    slog_info ("Info message with string variable: %s", sBuffer);

    /* Note message */
    slog_note ("Note message with integer variable: %d", nInteger);

    /* Trace thread id and print in output */
    slog_config_get (&slgCfg);
    slgCfg.nTraceTid = 1;
    slog_config_set (&slgCfg);

    /* Debug message with string and integer */
    slog_debug ("Debug message with enabled thread id tracing");

    /* Error message with errno string (in this case must be 'Success')*/
    slog_error ("Error message with errno string: %s", strerror(errno));

    // Disable trace tag
    // slog_disable (SLOG_TRACE);

    // This will never be printed while SLOG_TRACE is disabled by slog_disable() function 
    // slog_trace ("Test log with disabled tag");

    /* Enable file logger and color the whole log output instead of coloring only tags*/
    slog_config_get (&slgCfg);
    slgCfg.eColorFormat = SLOG_COLOR_FULL;
    slgCfg.nToFile = 0;
    slog_config_set (&slgCfg);

    /* Print message and save log in the file */
    slog_debug ("Debug message in the file with full line color enabled");

    /* Enable trace tag */
    slog_enable (SLOG_TRACE);

    /* We can trace function and line number with and without output message */
    slog_trace ("Trace message throws source location");

    /* Fatal error message */
    slog_fatal ("Fatal message also throws source location");

    // Disable output coloring
    slog_config_get (&slgCfg);
    slgCfg.eColorFormat = SLOG_COLOR_DISABLE;
    slog_config_set (&slgCfg);

    slog_debug ("Disabled output coloring");

    /* Just throw source location without output message */
    slog_trace();
    slog_debug ("Above we traced source location without output message");

    slog_enable (SLOG_FLAGS_ALL);
    // end of testing slog

    pthread_t tid;
    for (int i = 0; i < atoi (argv[4]); i++) {
        ArgsStruct *args = malloc (sizeof *args);
        args->configurationFile = argv[1];
        args->host = argv[2]; // No port argument yet, port is hard coded to 443
        args->iterations = atoi (argv[3]);
        args->threadId = i;
        args->range = atoi (argv[5]);
        if (pthread_create (&tid, NULL, workerThread, args)) {
            free (args);
        }
        slog_trace ("%s, worker thread: %d\n", __FUNCTION__, i);
    }

    // Wait for worker thread to finish
    // sleep (1);
    pthread_join (tid, NULL);
}

