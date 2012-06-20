/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Copyright (C) 2006 Red Hat, Inc.
 * Copyright (C) 2011 NORDUnet A/S.
 * Copyright 2012 School of Computer Science and Engineering, Hebrew University
 *                of Jerusalem.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *    1. Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *
 *    2. Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER
 * OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "otp.h"
#include <krb5/preauth_plugin.h>
#include "asn1/PA-OTP-CHALLENGE.h"
#include "asn1/PA-OTP-REQUEST.h"
#include "asn1/PA-OTP-ENC-REQUEST.h"

void
CLIENT_DEBUG(const char *format, ...)
{
#if defined(DEBUG)
    va_list pvar;
    char *s = NULL;
    size_t fmtlen;

    fmtlen = strlen(format) + 9;
    s = malloc(fmtlen);
    if (s != NULL)
        snprintf(s, fmtlen, "OTP PA: %s", format);
    va_start(pvar, format);
    vfprintf(stderr, s ? s : format, pvar);
    va_end(pvar);
    free(s);
#endif
}

static krb5_preauthtype otp_client_supported_pa_types[] = {
    KRB5_PADATA_OTP_CHALLENGE,
    0
};

static int
otp_client_init(krb5_context context, krb5_clpreauth_moddata *moddata_out)
{
    struct otp_client_ctx *ctx = NULL;

    ctx = calloc(1, sizeof(*ctx));
    if (ctx == NULL) {
        return ENOMEM;
    }
    *moddata_out = (krb5_clpreauth_moddata) ctx;
    return 0;
}

static void
otp_client_fini(krb5_context context, krb5_clpreauth_moddata moddata)
{
    struct otp_client_ctx *ctx = (struct otp_client_ctx *) moddata;

    if (ctx == NULL) {
        return;
    }
    free(ctx->otp);
    free(ctx->token_id);
    free(ctx);
}

static int
otp_client_get_flags(krb5_context context, krb5_preauthtype pa_type)
{
    return PA_REAL;
}

static krb5_error_code
otp_client_gic_opts(krb5_context context,
                    krb5_clpreauth_moddata moddata,
                    krb5_get_init_creds_opt *gic_opt,
                    const char *attr,
                    const char *value)
{
    struct otp_client_ctx *otp_ctx = (struct otp_client_ctx *) moddata;

    if (otp_ctx == NULL) {
        CLIENT_DEBUG("Missing context.\n");
        return KRB5_PREAUTH_FAILED;
    }

    if (strcmp(attr, "OTP") == 0) {
        if (otp_ctx->otp != NULL) {
            krb5_set_error_message(context, KRB5_PREAUTH_FAILED,
                                   "OTP can not be given twice.\n");
            return KRB5_PREAUTH_FAILED;
        }
        otp_ctx->otp = strdup(value);
        if (otp_ctx->otp == NULL) {
            krb5_set_error_message(context, KRB5_PREAUTH_FAILED,
                                   "Unable to copy OTP.\n");
            return ENOMEM;
        }
        CLIENT_DEBUG("Got OTP [%s].\n", otp_ctx->otp);
        return 0;
    }

    if (strcmp(attr, "OTP_TOKENID") == 0) {
        if (otp_ctx->token_id != NULL) {
            krb5_set_error_message(context, KRB5_PREAUTH_FAILED,
                                   "OTP_TOKENID can not be given twice.\n");
            return KRB5_PREAUTH_FAILED;
        }
        otp_ctx->token_id = strdup(value);
        if (otp_ctx->token_id == NULL) {
            krb5_set_error_message(context, KRB5_PREAUTH_FAILED,
                                   "Unable to copy OTP_TOKENID.\n");
            return ENOMEM;
        }
        CLIENT_DEBUG("Got OTP_TOKENID [%s].\n", otp_ctx->token_id);
        return 0;
    }

    return 0;
}

static krb5_error_code
otp_client_process(krb5_context context,
                   krb5_clpreauth_moddata moddata,
                   krb5_clpreauth_modreq modreq,
                   krb5_get_init_creds_opt *opt,
                   krb5_clpreauth_callbacks cb,
                   krb5_clpreauth_rock rock,
                   krb5_kdc_req *request,
                   krb5_data *encoded_request_body,
                   krb5_data *encoded_previous_request,
                   krb5_pa_data *pa_data,
                   krb5_prompter_fct prompter,
                   void *prompter_data,
                   krb5_pa_data ***pa_data_out)
{
    krb5_error_code retval = 0;
    krb5_keyblock *as_key = NULL;
    krb5_pa_data *pa = NULL;
    krb5_pa_data **pa_array = NULL;
    struct otp_client_ctx *otp_ctx = (struct otp_client_ctx *) moddata;
    PA_OTP_REQUEST_t *otp_req = NULL;
    krb5_data encoded_otp_req;
    PA_OTP_CHALLENGE_t *otp_challenge = NULL;
    krb5_data encoded_otp_challenge;
    size_t size;
    krb5_prompt prompt[1] = {{0,0,0}};
    int hidden = 0;
    char* buffer = NULL;
    char* c;
    krb5_data data;
    krb5_data nonce;
    krb5_enc_data encrypted_nonce;
    PA_OTP_ENC_REQUEST_t encData;
    asn_dec_rval_t drval;
    asn_enc_rval_t erval;

    /* Use FAST armor key as response key.  */
    as_key = cb->fast_armor(context, rock);
    if (as_key == NULL) {
        CLIENT_DEBUG("Missing armor key.\n");
        goto cleanup;
    }

    retval = cb->set_as_key(context, rock, as_key);
    if (retval != 0) {
        CLIENT_DEBUG("Unable to set reply key.\n");
        goto cleanup;
    }

    memset(&data, 0, sizeof(data));
    memset(&nonce, 0, sizeof(nonce));

    CLIENT_DEBUG("Got [%d] bytes pa-data type [%d].\n", pa_data->length,
                 pa_data->pa_type);

    if (pa_data->pa_type == KRB5_PADATA_OTP_CHALLENGE) {
        if (pa_data->length != 0) {
            encoded_otp_challenge.data = (char *) pa_data->contents;
            encoded_otp_challenge.length = pa_data->length;
            drval = ber_decode(0, &asn_DEF_PA_OTP_CHALLENGE, (void**)&otp_challenge, encoded_otp_challenge.data, encoded_otp_challenge.length);
            if (drval.code != RC_OK) {
                retval = EINVAL;
                goto cleanup;
            }
        }

        if (otp_challenge->nonce.buf == NULL) {
            CLIENT_DEBUG("Missing nonce in OTP challenge.\n");
            retval = EINVAL;
            goto cleanup;
        }

        otp_req = calloc(1, sizeof(*otp_req));
        if (otp_req == NULL) {
            retval = ENOMEM;
            goto cleanup;
        }
        memset(otp_req, 0, sizeof(*otp_req));
        memset(&encData, 0, sizeof(encData));
        encData.nonce = otp_challenge->nonce;
        erval = der_encode(&asn_DEF_PA_OTP_ENC_REQUEST, &encData, otp_encoder, &nonce);
        if (erval.encoded == -1) {
            CLIENT_DEBUG("failed decoding encrypted data.\n");
            retval = EINVAL;
            goto cleanup;
        }
        retval = krb5_c_encrypt_length(context, as_key->enctype,
                                       nonce.length, &size);
        if (retval != 0) {
            CLIENT_DEBUG("krb5_c_encrypt_length failed.\n");
            goto cleanup;
        }
        memset(&encrypted_nonce, 0, sizeof(encrypted_nonce));
        encrypted_nonce.ciphertext.data = malloc(size);
        if (encrypted_nonce.ciphertext.data == NULL) {
            retval = ENOMEM;
            goto cleanup;
        }
        encrypted_nonce.ciphertext.length = size;

        retval = krb5_c_encrypt(context, as_key, KRB5_KEYUSAGE_PA_OTP_REQUEST,
                                NULL, &nonce, &encrypted_nonce);
        if (retval != 0) {
            CLIENT_DEBUG("Failed to encrypt nonce.\n");
            goto cleanup;
        }
        // FIXME, verify this, check error
        otp_req->encData.cipher.buf = (unsigned char*)encrypted_nonce.ciphertext.data;
        otp_req->encData.cipher.size = encrypted_nonce.ciphertext.length;
        otp_req->encData.etype = encrypted_nonce.enctype;
        asn_long2INTEGER(otp_req->encData.kvno, encrypted_nonce.kvno);

        pa = calloc(1, sizeof(krb5_pa_data));
        if (pa == NULL) {
            retval = ENOMEM;
            goto cleanup;
        }

        pa_array = calloc(2, sizeof(krb5_pa_data *));
        if (pa_array == NULL) {
            retval = ENOMEM;
            goto cleanup;
        }

        if (otp_ctx == NULL) {
            CLIENT_DEBUG("Missing client context.\n");
        }
        else {
            if (otp_ctx->otp == NULL) {
                /*
                  If we have otp_vendor, it will be the prompt and the
                  otp_service will be the banner. Otherwise the otp_service
                  will be the prompt.
                */

                /* FIXME: Find a way to select between several tokeninfo's. */
                // FIXME use better var than data
                if (otp_challenge->otp_tokenInfo.list.count > 0 &&
                    otp_challenge->otp_tokenInfo.list.array[0]->otp_vendor &&
                    otp_challenge->otp_tokenInfo.list.array[0]->otp_vendor->size > 0) {
                    data.data = strndup(otp_challenge->otp_tokenInfo.list.array[0]->otp_vendor->buf,
                                        UTF8String_length(otp_challenge->otp_tokenInfo.list.array[0]->otp_vendor));
                    if (data.data == NULL) {
                        retval = ENOMEM;
                        goto cleanup;
                    }
                    data.length = UTF8String_length(otp_challenge->otp_tokenInfo.list.array[0]->otp_vendor);
                } else if (otp_challenge->otp_service &&
                           otp_challenge->otp_service->size > 0) {
                    data.data = strndup(otp_challenge->otp_service->buf,
                                        UTF8String_length(otp_challenge->otp_service));
                    if (data.data == NULL) {
                        retval = ENOMEM;
                        goto cleanup;
                    }
                    data.length = UTF8String_length(otp_challenge->otp_service);
                } else {
                    buffer = strdup("OTP");
                    if (buffer == NULL) {
                        retval = ENOMEM;
                        goto cleanup;
                    }
                }
                if (data.data != NULL) {
                    buffer = calloc(1, data.length + 1);
                    if (buffer == NULL) {
                        retval = ENOMEM;
                        goto cleanup;
                    }
                    memcpy(buffer, data.data, data.length);
                }
                prompt[0].prompt = strdup(buffer);
                if (prompt[0].prompt == NULL) {
                    retval = ENOMEM;
                    goto cleanup;
                }

                /* Check if otp should be echoed. */
                c = buffer;
                while (*c != 0) {
                    if (*c == ' ') *c = '_';
                    ++c;
                }
                hidden = otp_profile_get_hidden(context->profile, buffer, krb5_princ_realm(ctx->krb5_context, request->client));
                CLIENT_DEBUG("otp_profile_get_hidden(%s) = %i\n", buffer, hidden);

                prompt[0].hidden = hidden;
                prompt[0].reply = calloc(1, sizeof(krb5_data));
                if (prompt[0].reply == NULL) {
                    retval = ENOMEM;
                    goto cleanup;
                }
                prompt[0].reply->length = 64;
                prompt[0].reply->data = calloc(1, 64);
                if (prompt[0].reply->data == NULL) {
                    retval = ENOMEM;
                    goto cleanup;
                }

                free(buffer);
                if (otp_challenge->otp_tokenInfo.list.count > 0 &&
                    otp_challenge->otp_tokenInfo.list.array[0]->otp_vendor &&
                    otp_challenge->otp_tokenInfo.list.array[0]->otp_vendor->size > 0 &&
                    otp_challenge->otp_service &&
                    otp_challenge->otp_service->size > 0) {
                    buffer = calloc(1, otp_challenge->otp_service->size + 1);
                    memcpy(buffer, otp_challenge->otp_service->buf, otp_challenge->otp_service->size);
                } else {
                    buffer = NULL;
                }
                prompter(context, prompter_data, NULL,
                         buffer, 1, prompt);

                otp_ctx->otp = prompt[0].reply->data;
                free(prompt[0].reply);
                free(prompt[0].prompt);
                prompt[0].reply = NULL;
                prompt[0].prompt = NULL;
            }
#ifdef DEBUG
            if (strlen(otp_ctx->otp) == 0) {
                CLIENT_DEBUG("Got zero length OTP from client.\n");
            }
#endif
            if (otp_ctx->otp != NULL) {
                otp_req->otp_value = calloc(1, sizeof(*(otp_req->otp_value)));
                if (otp_req->otp_value == NULL) {
                    retval = ENOMEM;
                    goto cleanup;
                }
                otp_req->otp_value->buf = strdup(otp_ctx->otp);
                if (otp_req->otp_value->buf == NULL) {
                    retval = ENOMEM;
                    goto cleanup;
                }
                otp_req->otp_value->size = strlen(otp_ctx->otp);
            }
            if (otp_ctx->token_id != NULL) {
                otp_req->otp_tokenID->buf = otp_ctx->token_id;
                otp_req->otp_tokenID->size = strlen(otp_ctx->token_id);
            }
        }

        memset(&encoded_otp_req, 0, sizeof(encoded_otp_req));
        erval = der_encode(&asn_DEF_PA_OTP_REQUEST, otp_req, otp_encoder, &encoded_otp_req);
        if (erval.encoded == -1) {
            CLIENT_DEBUG("encode_krb5_pa_otp_req failed.\n");
            goto cleanup;
        }

        pa->length = encoded_otp_req.length;
        pa->contents = malloc(pa->length);
        if (pa->contents == NULL) {
            retval = ENOMEM;
            goto cleanup;
        }
        memcpy(pa->contents, encoded_otp_req.data, pa->length);
        pa->pa_type = KRB5_PADATA_OTP_REQUEST;

        pa_array[0] = pa;
        pa = NULL;
        *pa_data_out = pa_array;
        pa_array = NULL;
    } else {
        CLIENT_DEBUG("Unexpected PA data.\n");
        retval = EINVAL;
        goto cleanup;
    }

    CLIENT_DEBUG("Successfully processed PA data.\n");
    retval = 0;

 cleanup:
    krb5_free_data_contents(context, &encoded_otp_req);
    if (buffer != NULL)
        free(buffer);
    if (prompt[0].prompt != NULL)
        free(prompt[0].prompt);
    if (prompt[0].reply != NULL)
        free(prompt[0].reply);
    if (otp_req != NULL) {
        if (otp_req->otp_value != NULL) {
            if (otp_req->otp_value->buf != NULL)
                free(otp_req->otp_value->buf);
            free(otp_req->otp_value);
        }
        free(otp_req);
    }
    free(pa_array);
    free(pa);
    free(encrypted_nonce.ciphertext.data);
    asn_DEF_PA_OTP_CHALLENGE.free_struct(&asn_DEF_PA_OTP_CHALLENGE, otp_challenge, 0);
    krb5_free_data_contents(context, &nonce);
    krb5_free_data_contents(context, &data);
    return retval;
}

krb5_error_code
clpreauth_otp_initvt(krb5_context context, int maj_ver, int min_ver,
                     krb5_plugin_vtable vtable);

krb5_error_code
clpreauth_otp_initvt(krb5_context context, int maj_ver, int min_ver,
                     krb5_plugin_vtable vtable)
{
    krb5_clpreauth_vtable vt;

    if (maj_ver != 1) {
        return KRB5_PLUGIN_VER_NOTSUPP;
    }
    vt = (krb5_clpreauth_vtable) vtable;
    vt->name = "otp";
    vt->pa_type_list = otp_client_supported_pa_types;
    vt->init = otp_client_init;
    vt->fini = otp_client_fini;
    vt->flags = otp_client_get_flags;
    vt->process = otp_client_process;
    vt->gic_opts = otp_client_gic_opts;
    return 0;
}
