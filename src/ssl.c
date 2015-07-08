/*
 * Developed by Nicolas Martyanoff
 * Copyright (c) 2015 Celticom
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "internal.h"

static char io_ssl_error_buf[C_ERROR_BUFSZ];

void
io_ssl_initialize(void) {
    SSL_library_init();
    ERR_load_crypto_strings();
    ERR_load_SSL_strings();
    OpenSSL_add_all_algorithms();
}

void
io_ssl_shutdown(void) {
    EVP_cleanup();
    ERR_free_strings();
}

const char *
io_ssl_get_error(void) {
    char *ptr;
    size_t len;
    bool first;

    ptr = io_ssl_error_buf;
    len = C_ERROR_BUFSZ;

    first = true;

    for (;;) {
        unsigned long errcode;
        const char *errstr;
        size_t errlen;

        errcode = ERR_get_error();
        if (errcode == 0)
            break;

        if (!first) {
            c_strlcpy(ptr, ", ", len);

            ptr += 2;
            len -= 2;
            if (len <= 0)
                break;
        }

        errstr = ERR_error_string(errcode, NULL);
        c_strlcpy(ptr, errstr, len);

        errlen = strlen(errstr);
        ptr += errlen;
        len -= errlen;
        if (len <= 0)
            break;

        first = false;
    }

    if (ptr == io_ssl_error_buf)
        c_strlcpy(ptr, "empty ssl error queue", len);

    return io_ssl_error_buf;
}

DH *
io_ssl_dh_new(const char *path) {
    BIO *bio;
    DH *dh;

    bio = BIO_new_file(path, "r");
    if (!bio) {
        c_set_error("cannot open file: %s", io_ssl_get_error());
        return NULL;
    }

    dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
    if (!dh) {
        c_set_error("cannot read dh parameters: %s", io_ssl_get_error());
        BIO_free(bio);
        return NULL;
    }

    BIO_free(bio);
    return dh;
}

void
io_ssl_dh_delete(DH *dh) {
    if (!dh)
        return;

    DH_free(dh);
}

SSL_CTX *
io_ssl_ctx_new_client(const struct io_ssl_client_cfg *cfg) {
    const char *ciphers;
    long options, mode;
    int verify_mode;
    SSL_CTX *ctx;

    ctx = SSL_CTX_new(TLSv1_client_method());
    if (!ctx) {
        c_set_error("cannot create context: %s", io_ssl_get_error());
        return NULL;
    }

    options = SSL_OP_ALL /* all bug workarounds */
            | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 /* insecure protocols */
            | SSL_OP_CIPHER_SERVER_PREFERENCE;
    SSL_CTX_set_options(ctx, options);

    mode = SSL_MODE_ENABLE_PARTIAL_WRITE
         | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER;
    SSL_CTX_set_mode(ctx, mode);

    ciphers = cfg->ciphers;
    if (!ciphers)
        ciphers = "HIGH:@STRENGTH";
    if (SSL_CTX_set_cipher_list(ctx, ciphers) == 0) {
        c_set_error("cannot set ciphers: %s", io_ssl_get_error());
        goto error;
    }

    verify_mode = SSL_VERIFY_PEER;

    SSL_CTX_set_verify(ctx, verify_mode, NULL);
    SSL_CTX_set_verify_depth(ctx, 9);

    if (!cfg->ca_cert_path && !cfg->ca_cert_directory) {
        c_set_error("missing ca certificate or ca certificate directory");
        goto error;
    }
    if (SSL_CTX_load_verify_locations(ctx, cfg->ca_cert_path,
                                      cfg->ca_cert_directory) != 1) {
        if (cfg->ca_cert_path) {
            c_set_error("cannot load ca certificate from %s: %s",
                        cfg->ca_cert_path, io_ssl_get_error());
        } else {
            c_set_error("cannot set ca certificate directory: %s",
                        io_ssl_get_error());
        }
        goto error;
    }

    return ctx;

error:
    SSL_CTX_free(ctx);
    return NULL;
}

SSL_CTX *
io_ssl_ctx_new_server(const struct io_ssl_server_cfg *cfg) {
    const char *ciphers;
    long options, mode;
    int verify_mode;
    SSL_CTX *ctx;

    ctx = SSL_CTX_new(TLSv1_server_method());
    if (!ctx) {
        c_set_error("cannot create context: %s", io_ssl_get_error());
        return NULL;
    }

    options = SSL_OP_ALL /* all bug workarounds */
            | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3
            | SSL_OP_CIPHER_SERVER_PREFERENCE;
    SSL_CTX_set_options(ctx, options);

    mode = SSL_MODE_ENABLE_PARTIAL_WRITE
         | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER;
    SSL_CTX_set_mode(ctx, mode);

    ciphers = cfg->ciphers;
    if (!ciphers)
        ciphers = "HIGH:@STRENGTH";
    if (SSL_CTX_set_cipher_list(ctx, ciphers) == 0) {
        c_set_error("cannot set ciphers: %s", io_ssl_get_error());
        goto error;
    }

    verify_mode = SSL_VERIFY_PEER;

    SSL_CTX_set_verify(ctx, verify_mode, NULL);
    SSL_CTX_set_verify_depth(ctx, 9);

    if (!cfg->cert_path) {
        c_set_error("missing certificate");
        goto error;
    }
    if (SSL_CTX_use_certificate_file(ctx, cfg->cert_path,
                                     SSL_FILETYPE_PEM) != 1) {
        c_set_error("cannot load certificate from %s: %s",
                    cfg->cert_path, io_ssl_get_error());
        goto error;
    }

    if (!cfg->key_path) {
        c_set_error("missing private key");
        goto error;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, cfg->key_path,
                                    SSL_FILETYPE_PEM) != 1) {
        c_set_error("cannot load private key from %s: %s",
                    cfg->key_path, io_ssl_get_error());
        goto error;
    }

    if (cfg->dh_path) {
        DH *dh;

        dh = io_ssl_dh_new(cfg->dh_path);
        if (!dh) {
            c_set_error("cannot load dh parameters from %s: %s",
                        cfg->dh_path, c_get_error());
            goto error;
        }

        if (SSL_CTX_set_tmp_dh(ctx, dh) != 1) {
            c_set_error("cannot use dh parameters from %s: %s",
                        cfg->dh_path, io_ssl_get_error());
            DH_free(dh);
            goto error;
        }

        io_ssl_dh_delete(dh);
    }

    return ctx;

error:
    SSL_CTX_free(ctx);
    return NULL;
}

void
io_ssl_ctx_delete(SSL_CTX *ctx) {
    if (!ctx)
        return;

    SSL_CTX_free(ctx);
}

SSL *
io_ssl_new(SSL_CTX *ctx, int sock) {
    SSL *ssl;

    ssl = SSL_new(ctx);
    if (!ssl) {
        c_set_error("cannot create ssl connection: %s", io_ssl_get_error());
        return NULL;
    }

    if (SSL_set_fd(ssl, sock) == 0) {
        c_set_error("cannot set ssl connection socket: %s",
                    io_ssl_get_error());
        SSL_free(ssl);
        return NULL;
    }

    return ssl;
}

void
io_ssl_delete(SSL *ssl) {
    if (!ssl)
        return;

    SSL_free(ssl);
}

ssize_t
io_ssl_read(SSL *ssl, struct c_buffer *buf, size_t sz, int *perr) {
    void *ptr;
    int ret;

    ptr = c_buffer_reserve(buf, sz);

    ret = SSL_read(ssl, ptr, sz);
    if (ret <= 0) {
        const char *errmsg;
        int err;

        err = SSL_get_error(ssl, ret);
        *perr = err;

        switch (err) {
        case SSL_ERROR_ZERO_RETURN:
            return 0;

        case SSL_ERROR_SYSCALL:
            if (errno == 0)
                return 0;

            errmsg = strerror(errno);
            break;

        default:
            errmsg = io_ssl_get_error();
            break;
        }

        c_set_error("cannot read ssl data: %s", errmsg);
        return -1;
    }

    c_buffer_increase_length(buf, (size_t)ret);
    return ret;
}

ssize_t
io_ssl_write(SSL *ssl, struct c_buffer *buf, size_t *psz) {
    int ret;

    if (*psz == 0)
        *psz = c_buffer_length(buf);

    ret = SSL_write(ssl, c_buffer_data(buf), *psz);
    if (ret <= 0) {
        const char *errmsg;
        int err;

        err = SSL_get_error(ssl, ret);

        switch (err) {
        case SSL_ERROR_ZERO_RETURN:
            return 0;

        case SSL_ERROR_SYSCALL:
            if (errno == 0)
                return 0;

            errmsg = strerror(errno);
            break;

        default:
            errmsg = io_ssl_get_error();
            break;
        }

        c_set_error("cannot write ssl data: %s", errmsg);
        return -1;
    }

    c_buffer_skip(buf, (size_t)ret);

    *psz = 0;
    return ret;
}
