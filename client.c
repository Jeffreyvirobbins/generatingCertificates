#include "common.h"

int tcpConnect (char *host) {

    struct hostent *hp;
    struct sockaddr_in addr;
    int sock;

    if (!(hp = gethostbyname (host))) {
        berrExit ("Could not resolve host");
    }

    memset (&addr, 0, sizeof (addr));
    addr.sin_addr = *(struct in_addr *) hp->h_addr_list[0];
    addr.sin_family = AF_INET;
    addr.sin_port = htons (PORT);

    // prints details of hp
    /*
       while (*hp->h_aliases) {
       printf("%lu %d %s %s, alias: %s\n", pthread_self(), __LINE__, __FILE__, __FUNCTION__, *hp->h_aliases ++);
       }

       while (*hp->h_addr_list) {
       struct in_addr a;
       bcopy (*hp->h_addr_list ++, (char *) &a, sizeof(a));
       printf ("%lu %d %s %s, IP address: %s\n", pthread_self(), __LINE__, __FILE__, __FUNCTION__, inet_ntoa(a));
       break;
       }
       */

    // Big mistake here
    //if ((sock = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP) < 0)) {
    if ((sock = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
        errExit ("Could not create socket\n");
    }

    int status = connect (sock, (struct sockaddr *) &addr, sizeof (addr));
    slog_trace ("%s, status: %d", __FUNCTION__, status);

    // if (connect (sock, (struct sockaddr *) &addr, sizeof (addr)) < 0) {
    if (status < 0) {
        errExit ("Could not connect socket\n");
    }

    slog_trace ("%s, Socket layer connects success to %s:%d", __FUNCTION__, hp->h_name, PORT);
    return sock;
}


/**
 *
 */
void checkCertificateChain (SSL *ssl, char *host) {

    X509 *peerCertificate;
    char peer_CN[256];

    // verify server certificate
    if (SSL_get_verify_result (ssl) != X509_V_OK) {
        berrExit ("Certificate does not verify");
    }

    slog_trace ("%s, Server certificate verified", __FUNCTION__);
    return;

    // The chain length is automaticslly checked by OpenSSL when we set the verify depth in the ctx
    // Asll we need to here is to check that the CN matches
    
    // Note, pnn server cannot pass this check
    // This is the post-connections assertation in p134 Network Security with OpenSSL
    /*
     * https://linux.die.net/man/3/x509_name_get_text_by_nid
     * Notes
     X509_NAME_get_text_by_NID() and X509_NAME_get_text_by_OBJ() 
     are legacy functions which have various limitations 
     which make them of minimal use in practice. 
     They can only find the first matching entry and will copy the contents of the field verbatim: 
     this can be highly confusing if the target is a muticharacter string type like a BMPString or a UTF8String.

     For a more general solution X509_NAME_get_index_by_NID() or X509_NAME_get_index_by_OBJ() 
     should be used followed by X509_NAME_get_entry() on any matching indices 
     and then the various X509_NAME_ENTRY utility functions on the result.
     */
    // Check the common name
    peerCertificate = SSL_get_peer_certificate (ssl);
    X509_NAME_get_text_by_NID (
            X509_get_subject_name (peerCertificate), 
            NID_commonName, 
            peer_CN,
            256
            );
    if (strcasecmp (peer_CN, host)) {
        berrExit ("Common name does not match host name");
    }

    slog_trace ("%s, Server certificate verified", __FUNCTION__);
    return;
}

