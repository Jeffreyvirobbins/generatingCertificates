#include "common.h"
#include "pnnMessage.h"

/**
 * If iterations is 0, then infinite loop
 */
int readWrite (int iterations, SSL *ssl, int sock) {

    int width;
    int r, c2sl = 0, c2s_offset = 0, s2cl = 0;
    fd_set readfds, writefds;
    int shutdown_wait = 0;

    char c2sMessageName[BUFSIZZ];
    // Note the type changed
    unsigned char c2s[BUFSIZZ], s2c[BUFSIZZ];

    // First we make the socket nonblocking
    /*
    int ofcmode = fcntl (sock, F_GETFL, 0);
    ofcmode |= O_NDELAY;
    if (fcntl (sock, F_SETFL, ofcmode)) {
        err_exit ("Cound't make socket nonblocking");
    }
    */
    slog_trace ("%s, sock: %d", __FUNCTION__, sock);
    width = sock + 1;

    int i = 0; 
    while (i == 0 || i < iterations) {

        FD_ZERO (&readfds);
        FD_ZERO (&writefds);
        FD_SET (sock, &readfds);
        FD_SET (sock, &writefds);

        /*
        // If we've still get data to write, then don't try to read
        if (c2sl) {
            FD_SET (sock, &writefds);
        }
        else {
            FD_SET (fileno (stdin), &readfds);
        }

        // TODO, thread level select?
        // Do we really need it?
        slog_trace ("%s, To select", __FUNCTION__);
           r = select (width, &readfds, &writefds, 0, 0);
           if (r == 0) {
           slog_trace ("%s, select return 0", __FUNCTION__);
           continue;
           }
           slog_trace ("%s, Done select", __FUNCTION__);
        // Now check if there's data to read
        // To clean the buffer?
        // Add this section also mean t add select()?
        if (FD_ISSET (sock, &readfds)) {
            s2cl = 0;
            do {
                r = SSL_read (ssl, s2c, BUFSIZZ);
                s2cl += r;
                int ssl_error_value = SSL_get_error (ssl, r);

                switch (ssl_error_value) {

                    case SSL_ERROR_NONE:
                        slog_trace ("%s, SSL_ERROR_NONE: %s", __FUNCTION__,
                                s2c
                                );
                        // fwrite (s2c, 1, r, stdout);
                        break;

                    case SSL_ERROR_ZERO_RETURN:
                        slog_trace ("%s, SSL_ERROR_ZERO_RETURN", __FUNCTION__);
                        // End of data
                        //
                        //   if (!shutdown_wait) {
                          // SSL_shutdown (ssl);
                          // }
                          // goto end;
                           //

                        break;

                    case SSL_ERROR_WANT_READ:
                        // Do nothing here
                        slog_trace ("%s, SSL_ERROR_WANT_READ", __FUNCTION__);
                        break;

                    default: 
                        slog_trace ("%s, SSL_ERROR_default, SSL read problem", __FUNCTION__);
                        berr_exit ("SSL read problem");
                        break;
                }
            } while (SSL_pending (ssl));

            if (s2cl > 0) {
                // print_buffer (s2c, s2cl);
                dumpBuffer (__LINE__, __FILE__, __FUNCTION__, s2cl, "s2c", s2c, 2);
            }
        }
*/
        // Construct a payload in buffer c2s
        // construct messages "demux"
        encodeUcs (&c2sl, c2s);
        slog_trace ("%s, Send to server with length: %d", __FUNCTION__, c2sl);
        dumpBuffer (__LINE__, __FILE__, __FUNCTION__, c2sl, "c2s", c2s, 2);

        // write it
        // if (c2sl && FD_ISSET (sock, &writefds)) 
        if (FD_ISSET (sock, &writefds)) {
            r = SSL_write (ssl, c2s + c2s_offset, c2sl);
            slog_trace ("%s, SSL_write length: %d", __FUNCTION__, r);
            int sslErrorValue = SSL_get_error (ssl, r);
            switch (sslErrorValue) {

                case SSL_ERROR_NONE:
                    slog_trace ("%s, SSL_ERROR_NONE", __FUNCTION__);
                    c2sl -= r;
                    c2s_offset += r;
                    break;

                    // We should have blocked
                case SSL_ERROR_WANT_WRITE:
                    slog_trace ("%s, SSL_ERROR_WANT_WRITE", __FUNCTION__);
                    break;

                    // all cases below are abnormal cases
                case SSL_ERROR_WANT_READ:
                    slog_trace ("%s, SSL_ERROR_WANT_READ", __FUNCTION__);
                    berrExit ("SSL write problem");
                    break;

                case SSL_ERROR_ZERO_RETURN:
                    slog_trace ("%s, SSL_ERROR_ZERO_RETURN", __FUNCTION__);
                    berrExit ("SSL write problem");
                    break;

                case SSL_ERROR_WANT_CONNECT:
                    slog_trace ("%s, SSL_ERROR_WANT_CONNECT", __FUNCTION__);
                    berrExit ("SSL write problem");
                    break;

                case SSL_ERROR_WANT_ACCEPT:
                    slog_trace ("%s, SSL_ERROR_WANT_ACCEPT", __FUNCTION__);
                    berrExit ("SSL write problem");
                    break;

                case SSL_ERROR_WANT_X509_LOOKUP:
                    slog_trace ("%s, SSL_ERROR_WANT_X509_LOOKUP", __FUNCTION__);
                    berrExit ("SSL write problem");
                    break;

                case SSL_ERROR_WANT_ASYNC:
                    slog_trace ("%s, SSL_ERROR_WANT_ASYNC", __FUNCTION__);
                    berrExit ("SSL write problem");
                    break;

                case SSL_ERROR_WANT_ASYNC_JOB:
                    slog_trace ("%s, SSL_ERROR_WANT_ASYNC_JOB", __FUNCTION__);
                    berrExit ("SSL write problem");
                    break;

                case SSL_ERROR_SYSCALL:
                    slog_trace ("%s, SSL_ERROR_SYSCALL", __FUNCTION__);
                    berrExit ("SSL write problem");
                    break;

                case SSL_ERROR_SSL:
                    slog_trace ("%s, SSL_ERROR_SSL", __FUNCTION__);
                    berrExit ("SSL write problem");
                    break;

                    // Some other error
                default: 
                             // ERR_error_string() match ERR_get_error()
                             //                Not match SSL_get_error()
                    slog_trace ("%s, SSL_ERROR_default, SSL_get_error returns: %d", __FUNCTION__,
                            sslErrorValue
                            );
                    berrExit ("SSL write problem");
                    break;
            }
        }

        // Add to buffer again
        encodeUcs (&c2sl, c2s);

        // For debug purpose, only run one iteration
        // Can server side destory session?

        sleep (1);

        if (iterations == 0) {
            i = 0; // infinitely loop
            slog_trace ("%s, infinitely loop", __FUNCTION__);
        }
        else {
            i ++;
            slog_trace ("%s, iteration: %d", __FUNCTION__, i);
        }
    } // while 

    slog_trace ("%s, Finished iteration: %d", __FUNCTION__, i);

end:
    SSL_free (ssl);
    close (sock);
    return 0;
}

