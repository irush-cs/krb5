/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Copyright (C) 2006 Red Hat, Inc.
 * Copyright (C) 2011 NORDUnet A/S.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Red Hat, Inc., nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
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

/*
  A successful OTP authentication follows this process on the KDC.

  (1) The kdb is searched for an OTP token identity, matching what
      might be found in preauth attribute "OTP_TOKENID".

  (2) An authentication method, i.e. a function, is picked from the
      result of (1).

  (3) The authentication method from (2) is invoked with a potential
      data blob found in (1).

  (4) The result from (3) is returned.

  OTP info per principal is stored in the kdb using the
  KRB5_TL_STRING_ATTRS tl-data type.  The keyword used is "otp-token".
  The format of the value is

    <otp-token-id>:<method-name>:<data-blob>

    otp-token-id identifies a unique token on the form of a class A
    OATH token identifier as specified in
    http://www.openauthentication.org/oath-id: MMTTUUUUUUUU, where
    M=manufacturer, T=token type and U=manufacturer unique id.

    method-name identifies the method to use for authentication
    (f.ex. "basicauth", "ykclient" or "nativehotp").  The method name
    maps to a function in the OTP plugin or possibly in a second-level
    plugin.  A method may use the prefix "otp_<method-name>_" for
    profile names in krb5.conf.

    data-blob is a binary blob passed to the authentication method
    chosen based on method-name.

  A token id may be passed to the KDC using the pre-authentication
  attribute OTP_TOKENID ("kinit -X OTP_TOKENID=mytoken ...").  If no
  OTP_TOKENID is provided, the first token id found is being used.

  If OTP is not passed to the client by other means (gic), the standard
  prompter is used with the otp_service and/or otp_vendor as prompt (excluding
  trailing spaces and semicolons). The otp_hidden option in krb5.conf can be
  used to specify which otp_service will have a hidden prompt (echo
  password). The option can come either in libdefaults or inside the realms
  sections, and can be either boolean or a section with per prompt option. e.g.

      [libdefaults]
          ...
          otp_hidden = {
              My_OTP = false
              OTP_Password = true
          }

      [realms]
          ...
          MY.REALM = {
              ...
              otp_hidden = false
          }

  This should be set on the client machine configuration.

  The otp_service can be set on the server either on the libdefaults section or
  in a specific realm, using the otp_service configuration string. e.g.

      [libdefaults]
          ...
          otp_service = Default OTP Service

      [realms]
          MY.REALM = {
              ...
              otp_service = MY.REALM OTP Service

 */


// for addresses
#include "k5-int.h"
#include "../kdc/kdc_util.h"

#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>

#include "../lib/krb5/asn.1/asn1_encode.h"
#include <krb5/preauth_plugin.h>

/* FIXME: Belong in krb5.hin.  */
#define KRB5_KEYUSAGE_PA_OTP_REQUEST 		45
#define KRB5_PADATA_OTP_CHALLENGE  141
#define KRB5_PADATA_OTP_REQUEST    142
#define KRB5_PADATA_OTP_CONFIRM    143
#define KRB5_PADATA_OTP_PIN_CHANGE 144

#define OTP_FLAG_RESERVED 0
#define OTP_FLAG_NEXT_OTP (1u<<1)
#define OTP_FLAG_COMBINE (1u<<2)
#define OTP_FLAG_PIN_REQUIRED (1u<<3)
#define OTP_FLAG_PIN_NOT_REQUIRED (1u<<4)
#define OTP_FLAG_MUST_ENCRYPT_NONCE (1u<<5)

/* A (class A) OATH token identifier as specified in
   http://www.openauthentication.org/oath-id: MMTTUUUUUUUU.
   M=manufacturer, T=token type, U=manufacturer unique id.  */
#define TOKEN_ID_LENGTH 12

#include "otp.h"
#if defined (OTP_PREAUTH_ENABLE_BASICAUTH)
#include "m_basicauth.h"
#endif
#if defined (OTP_PREAUTH_ENABLE_YKCLIENT)
#include "m_ykclient.h"
#endif

/* Configured OTP methods.  */
struct otp_method otp_methods[] = {
#if defined (OTP_PREAUTH_ENABLE_BASICAUTH)
    {"basicauth", otp_basicauth_server_init, 0, NULL, NULL},
#endif
#if defined (OTP_PREAUTH_ENABLE_YKCLIENT)
    {"ykclient", otp_ykclient_server_init, 0, NULL, NULL},
#endif
    {NULL, NULL, 0, NULL, NULL}
};


/**********************/
/* Helper functions.  */
void
SERVER_DEBUG(errcode_t code, const char *format, ...)
{
#if defined(DEBUG)
    va_list ap;

    va_start(ap, format);
    com_err_va("OTP PA", code, format, ap);
    va_end(ap);
#endif
}

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


/************/
/* Client.  */
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
    krb5_pa_otp_req otp_req;
    krb5_data *encoded_otp_req = NULL;
    krb5_pa_otp_challenge *otp_challenge = NULL;
    krb5_data encoded_otp_challenge;
    size_t size;
    krb5_prompt prompt[1] = {{0,0,0}};
    int hidden = 0;
    char* buffer = NULL;
    char* c;
    krb5_data *data = NULL;

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

    CLIENT_DEBUG("Got [%d] bytes pa-data type [%d].\n", pa_data->length,
                 pa_data->pa_type);

    if (pa_data->pa_type == KRB5_PADATA_OTP_CHALLENGE) {
        if (pa_data->length != 0) {
            encoded_otp_challenge.data = (char *) pa_data->contents;
            encoded_otp_challenge.length = pa_data->length;
            retval = decode_krb5_pa_otp_challenge(&encoded_otp_challenge,
                                                  &otp_challenge);
            if (retval != 0) {
                goto cleanup;
            }
        }

        if (otp_challenge->nonce.data == NULL) {
            CLIENT_DEBUG("Missing nonce in OTP challenge.\n");
            retval = EINVAL;
            goto cleanup;
        }

        memset(&otp_req, 0, sizeof(otp_req));
        retval = krb5_c_encrypt_length(context, as_key->enctype,
                                       otp_challenge->nonce.length, &size);
        otp_req.enc_data.ciphertext.length = size;
        if (retval != 0) {
            CLIENT_DEBUG("krb5_c_encrypt_length failed.\n");
            goto cleanup;
        }
        otp_req.enc_data.ciphertext.data =
            malloc(otp_req.enc_data.ciphertext.length);
        if (otp_req.enc_data.ciphertext.data == NULL) {
            retval = ENOMEM;
            goto cleanup;
        }

        retval = krb5_c_encrypt(context, as_key, KRB5_KEYUSAGE_PA_OTP_REQUEST,
                                NULL, &otp_challenge->nonce, &otp_req.enc_data);
        if (retval != 0) {
            CLIENT_DEBUG("Failed to encrypt nonce.\n");
            goto cleanup;
        }

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
                if (otp_challenge->n_otp_tokeninfo > 0 &&
                    otp_challenge->otp_tokeninfo[0].otp_vendor.length > 0) {
                    data = &otp_challenge->otp_tokeninfo[0].otp_vendor;
                } else if (otp_challenge->otp_service.length > 0) {
                    data = &otp_challenge->otp_service;
                } else {
                    buffer = strdup("OTP");
                    if (buffer == NULL) {
                        retval = ENOMEM;
                        goto cleanup;
                    }
                }
                if (data != NULL) {
                    buffer = calloc(1, data->length + 1);
                    if (buffer == NULL) {
                        retval = ENOMEM;
                        goto cleanup;
                    }
                    memcpy(buffer, data->data, data->length);
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
                if (otp_challenge->n_otp_tokeninfo > 0 &&
                    otp_challenge->otp_tokeninfo[0].otp_vendor.length > 0 &&
                    otp_challenge->otp_service.length > 0) {
                    buffer = calloc(1, otp_challenge->otp_service.length + 1);
                    memcpy(buffer, otp_challenge->otp_service.data, otp_challenge->otp_service.length);
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
                otp_req.otp_value.data = otp_ctx->otp;
                otp_req.otp_value.length = strlen(otp_ctx->otp);
            }
            if (otp_ctx->token_id != NULL) {
                otp_req.otp_token_id.data = otp_ctx->token_id;
                otp_req.otp_token_id.length = strlen(otp_ctx->token_id);
            }
        }

        retval = encode_krb5_pa_otp_req(&otp_req, &encoded_otp_req);
        if (retval != 0) {
            CLIENT_DEBUG("encode_krb5_pa_otp_req failed.\n");
            goto cleanup;
        }

        pa->length = encoded_otp_req->length;
        pa->contents = malloc(pa->length);
        if (pa->contents == NULL) {
            retval = ENOMEM;
            goto cleanup;
        }
        memcpy(pa->contents, encoded_otp_req->data, pa->length);
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
    if (encoded_otp_req != NULL)
        krb5_free_data(context, encoded_otp_req);
    if (buffer != NULL)
        free(buffer);
    if (prompt[0].prompt != NULL)
        free(prompt[0].prompt);
    if (prompt[0].reply != NULL)
        free(prompt[0].reply);
    free(pa_array);
    free(pa);
    if (otp_req.enc_data.ciphertext.data != NULL)
        free(otp_req.enc_data.ciphertext.data);
    if (otp_challenge != NULL) {
        krb5_free_data_contents(context, &otp_challenge->nonce);
        krb5_free_data_contents(context, &otp_challenge->otp_service);
        /* free(otp_challenge->otp_tokeninfo); */
        krb5_free_data_contents(context, &otp_challenge->salt);
        krb5_free_data_contents(context, &otp_challenge->s2kparams);
        free(otp_challenge);
    }
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


/************/
/* Server.  */
static int
otp_server_get_flags(krb5_context context, krb5_preauthtype pa_type)
{
    return PA_HARDWARE | PA_REPLACES_KEY;
}


/* Find OTP info for principal in kdb.  */
static int
otp_server_pick_token(struct otp_server_ctx *ctx,
                      krb5_kdcpreauth_rock rock,
                      const char *token_id_hint,
                      krb5_kdcpreauth_callbacks pa_cb,
                      char **token_id_out,
                      struct otp_method **method_out,
                      char **blob_out)
{
    krb5_error_code retval = 0;
    int f;
    char *key = NULL;
    char *val = NULL;
    char *cp = NULL;
    char *saveptr = NULL;
    char *token_id = NULL;
    char *method_name = NULL;
    char *blob = NULL;

    *token_id_out = NULL;
    *method_out = NULL;
    *blob_out = NULL;

    key = strdup("otp-token9");
    if (key == NULL) {
        retval = ENOMEM;
        goto out;
    }
    /* TODO: Support more than 10 OTP tokens per principal (otp-token0
       to otp-token9).  */
    token_id = method_name = blob = NULL;
    for (f = 0; f < 10; f++, key[9]--) {
        pa_cb->free_string(ctx->krb5_context, rock, val);

        retval = pa_cb->get_string(ctx->krb5_context, rock, key, &val);
        if (retval != 0)
            goto out;

        /* val is on the form <otp-token-id>:<method-name>[:<data-blob>] */
        cp = strtok_r(val, ":", &saveptr);
        if (cp == NULL)
            continue;
        free(token_id);
        token_id = strdup(cp);
        cp = strtok_r(NULL, ":", &saveptr);
        if (cp == NULL)
            continue;
        free(method_name);
        method_name = strdup(cp);
        cp = strtok_r(NULL, ":", &saveptr);
        if (cp != NULL) {
            free(blob);
            blob = strdup(cp);
        }
        if (token_id_hint != NULL && strcmp(token_id, token_id_hint) == 0)
            break;
    }

    if (token_id == NULL) {
        SERVER_DEBUG(ENOENT, "Token id not found for principal.");
        retval = ENOENT;
        goto out;
    }
    assert(method_name != NULL);
    for (f = 0; otp_methods[f].name != NULL; f++) {
        if (strcmp(otp_methods[f].name, method_name) == 0) {
            *method_out = otp_methods + f;
        }
    }
    if (*method_out == NULL) {
        SERVER_DEBUG(ENOENT, "Authentication method %s not configured.", method_name);
        retval = ENOENT;
        goto out;
    }

    *token_id_out = token_id;
    *blob_out = blob;

 out:
    free(method_name);
    free(key);
    pa_cb->free_string(ctx->krb5_context, rock, val);
    return retval;
}

/* Free a request context. */
static void
otp_server_free_req_ctx(struct otp_req_ctx **request)
{
    if (*request == NULL)
        return;
    free((*request)->token_id);
    free((*request)->blob);
    free((*request)->from);
    free(*request);
    *request = NULL;
}

static void
otp_server_free_modreq(krb5_context context,
                       krb5_kdcpreauth_moddata moddata,
                       krb5_kdcpreauth_modreq modreq)
{
    otp_server_free_req_ctx((struct otp_req_ctx **) &modreq);
}

/* Create a request context with the client, blob, token and method,
   for use in the server edata and verify methods. */
static int
otp_server_create_req_ctx(struct otp_server_ctx *ctx,
                          krb5_kdcpreauth_rock rock,
                          const char *token_id_hint,
                          krb5_kdcpreauth_callbacks pa_cb,
                          struct otp_req_ctx **req_out)
{
    krb5_error_code retval = 0;
    struct otp_req_ctx *req = NULL;
    char fromstringbuf[70];
    char* fromstring = 0;

    *req_out = NULL;
    req = calloc(1, sizeof(struct otp_req_ctx));
    if (req == NULL)
        return ENOMEM;

    retval = otp_server_pick_token(ctx, rock, token_id_hint, pa_cb,
                                   &req->token_id, &req->method, &req->blob);
    if (retval != 0) {
        SERVER_DEBUG(retval, "Error getting OTP info for principal: %d.", retval);
        otp_server_free_req_ctx(&req);
        return retval;
    }

    fromstring = inet_ntop(ADDRTYPE2FAMILY (rock->from->address->addrtype),
                           rock->from->address->contents,
                           fromstringbuf, sizeof(fromstringbuf));

    if (fromstring)
        req->from = strdup(fromstring);

    SERVER_DEBUG(0, "Token id [%s] found; method [%s], blob [%s], from [%s].",
                 req->token_id, req->method->name, req->blob ? req->blob : "", req->from);
    *req_out = req;
    return 0;
}

static char *
get_config(struct otp_server_ctx *otp_ctx,
           const char *realm,
           const char *str)
{
    krb5_error_code retval = 0;
    krb5_context k5_ctx = NULL;
    char *realm_copy = NULL;
    profile_t profile = NULL;
    char *result = NULL;

    assert(otp_ctx != NULL);
    k5_ctx = otp_ctx->krb5_context;
    assert(k5_ctx != NULL);
    retval = krb5_get_profile(k5_ctx, &profile);
    if (retval != 0) {
        SERVER_DEBUG(retval, "%s: krb5_get_profile error.", __func__);
        goto out;
    }
    if (realm == NULL) {
        retval = krb5_get_default_realm(k5_ctx, &realm_copy);
        if (retval != 0) {
            SERVER_DEBUG(retval, "%s:  krb5_get_default_realm error.",
                         __func__);
            goto out;
        }
        realm = realm_copy;
    }
    retval = profile_get_string(profile, KRB5_CONF_REALMS, realm, str, NULL,
                                &result);
    if (retval != 0) {
        SERVER_DEBUG(retval, "%s: profile_get_string error.", __func__);
        result = NULL;
        goto out;
    }

 out:
    if (realm_copy != NULL) {
        krb5_free_default_realm(k5_ctx, realm_copy);
        realm_copy = NULL;
    }
    profile_release(profile);
    profile = NULL;
    return result;
}

static void
server_init_methods(struct otp_server_ctx *ctx)
{
    int f;
    int err;

    for (f = 0; otp_methods[f].name != NULL; f++) {
        struct otp_method *m = &otp_methods[f];
        err = m->init(ctx, get_config, &m->ftable, &m->context);
        if (err == 0) {
            m->enabled_flag = 1;
        }
        else {
            SERVER_DEBUG(err, "Failing init for method [%s].", m->name);
        }
    }
}

static krb5_error_code
otp_server_init(krb5_context krb5_ctx,
                krb5_kdcpreauth_moddata *moddata_out,
                const char **realmnames)
{
    struct otp_server_ctx *ctx = NULL;
    krb5_error_code retval = 0;

    assert(moddata_out != NULL);

    ctx = calloc(1, sizeof(*ctx));
    if (ctx == NULL) {
        retval = ENOMEM;
        goto errout;
    }
#ifdef DEBUG
    ctx->magic = MAGIC_OTP_SERVER_CTX;
#endif

    ctx->krb5_context = krb5_ctx;
    server_init_methods(ctx);
    *moddata_out = (krb5_kdcpreauth_moddata) ctx;

    return 0;

 errout:
    free (ctx);
    return retval;
}

static void
server_fini_methods(struct otp_server_ctx *ctx)
{
    int f;

    for (f = 0; otp_methods[f].name != NULL; f++) {
        struct otp_method *m = &otp_methods[f];
        if (m->enabled_flag) {
            assert(m->ftable);
            if (m->ftable->server_fini) {
                m->ftable->server_fini(m->context);
            }
            free (m->ftable);
        }
    }
}

static void
otp_server_fini(krb5_context context, krb5_kdcpreauth_moddata moddata)
{
    struct otp_server_ctx *ctx = (struct otp_server_ctx *) moddata;
    assert(ctx != NULL);

    server_fini_methods(ctx);
    free(ctx);
}

static void
otp_server_get_edata(krb5_context context,
                     krb5_kdc_req *request,
                     krb5_kdcpreauth_callbacks cb,
                     krb5_kdcpreauth_rock rock,
                     krb5_kdcpreauth_moddata moddata,
                     krb5_preauthtype pa_type,
                     krb5_kdcpreauth_edata_respond_fn respond,
                     void *arg)
{
    krb5_error_code retval = -1;
    krb5_keyblock *armor_key = NULL;
    krb5_pa_data *pa = NULL;
    krb5_pa_otp_challenge otp_challenge;
    krb5_data *encoded_otp_challenge = NULL;
    struct otp_server_ctx *otp_ctx = (struct otp_server_ctx *) moddata;
    struct otp_req_ctx *otp_req = NULL;
    krb5_timestamp now_sec;
    krb5_int32 now_usec;

    assert(otp_ctx != NULL);
    memset(&otp_challenge, 0, sizeof(otp_challenge));

    armor_key = cb->fast_armor(context, rock);
    if (armor_key == NULL) {
        SERVER_DEBUG(EINVAL, "No armor key found when preparing challenge.");
        (*respond)(arg,  EINVAL, NULL);
        return;
    }

    pa = calloc(1, sizeof(krb5_pa_data));
    if (pa == NULL) {
        (*respond)(arg, ENOMEM, NULL);
        return;
    }

    /* Create nonce from random data + timestamp.  Length of random
       data equals the length of the server key.  The timestamp is 4
       octets current time, seconds since the epoch and 4 bytes
       microseconds, both encoded in network byte order.  */
    otp_challenge.nonce.length = armor_key->length + 8;
    otp_challenge.nonce.data = (char *) malloc(otp_challenge.nonce.length);
    if (otp_challenge.nonce.data == NULL) {
        (*respond)(arg, ENOMEM, NULL);
        goto cleanup;
    }
    retval = krb5_c_random_make_octets(context, &otp_challenge.nonce);
    if (retval != 0) {
        SERVER_DEBUG(retval, "Unable to create random data for nonce.");
        (*respond)(arg, retval, NULL);
        goto cleanup;
    }
    retval = krb5_us_timeofday(context, &now_sec, &now_usec);
    if (retval != 0) {
        SERVER_DEBUG(retval, "Unable to get current time.");
        (*respond)(arg, retval, NULL);
        goto cleanup;
    }
    *((uint32_t *) (otp_challenge.nonce.data + armor_key->length)) =
        htonl(now_sec);
    *((uint32_t *) (otp_challenge.nonce.data + armor_key->length + 4)) =
        htonl(now_usec);

    otp_challenge.n_otp_tokeninfo = 1;
    otp_challenge.otp_tokeninfo = calloc(otp_challenge.n_otp_tokeninfo,
                                         sizeof(krb5_otp_tokeninfo));
    if (otp_challenge.otp_tokeninfo == NULL) {
        (*respond)(arg,  ENOMEM, NULL);
        goto cleanup;
    }

    /* Get the otp_service */
    otp_challenge.otp_service.data = otp_profile_get_service(context->profile, krb5_princ_realm(context, request->client));
    if (otp_challenge.otp_service.data != NULL)
        otp_challenge.otp_service.length = strlen(otp_challenge.otp_service.data);

    retval = otp_server_create_req_ctx(otp_ctx, rock, NULL, cb, &otp_req);
    if (retval != 0) {
        SERVER_DEBUG(retval, "Unable to create request context for edata.");
        (*respond)(arg, retval, NULL);
        goto cleanup;
    }

    /* Let the method set up a challenge (the tokeninfo) */
    if (otp_req->method->ftable->server_challenge) {
        retval = otp_req->method->ftable->server_challenge(otp_req,
                                                           &otp_challenge.otp_tokeninfo[0]);
        if (retval != 0) {
            SERVER_DEBUG(retval, "[%s] server_challenge failed.",
                         otp_req->method->name);
            (*respond)(arg, retval, NULL);
            goto cleanup;
        }
    } else {
        SERVER_DEBUG(0, "Method [%s] doesn't set a challenge.",
                     otp_req->method->name);
    }

    /* TODO: Delegate to otp methods to decide on the flags.  */
    otp_challenge.otp_tokeninfo[0].flags = 0;

    /* Encode challenge.  */
    retval = encode_krb5_pa_otp_challenge(&otp_challenge,
                                          &encoded_otp_challenge);
    if (retval != 0) {
        SERVER_DEBUG(retval, "Unable to encode challenge.");
        (*respond)(arg, retval, NULL);
        goto cleanup;
    }

    pa->pa_type = KRB5_PADATA_OTP_CHALLENGE;
    pa->length = encoded_otp_challenge->length;
    pa->contents = malloc(pa->length);
    if (pa->contents == NULL) {
        retval = ENOMEM;
        goto cleanup;
    }
    memcpy(pa->contents, encoded_otp_challenge->data, pa->length);
    (*respond)(arg, retval, pa);

 cleanup:
    if (encoded_otp_challenge != NULL)
        krb5_free_data(context, encoded_otp_challenge);
    if (otp_req != NULL)
        otp_server_free_req_ctx(&otp_req);
    if (otp_challenge.otp_service.length)
        free(otp_challenge.otp_service.data);
    if (otp_challenge.otp_tokeninfo != NULL) {
        krb5_free_data_contents(context, &otp_challenge.otp_tokeninfo->otp_vendor);
        free(otp_challenge.otp_tokeninfo);
    }
    if (otp_challenge.nonce.data != NULL)
        free(otp_challenge.nonce.data);
    if (retval != 0 && pa != NULL)
        free(pa);
}

static void
otp_server_verify_padata(krb5_context context,
                         krb5_data *req_pkt,
                         krb5_kdc_req *request,
                         krb5_enc_tkt_part *enc_tkt_reply,
                         krb5_pa_data *data,
                         krb5_kdcpreauth_callbacks cb,
                         krb5_kdcpreauth_rock rock,
                         krb5_kdcpreauth_moddata moddata,
                         krb5_kdcpreauth_verify_respond_fn respond,
                         void *arg)
{
    krb5_pa_otp_req *otp_req = NULL;
    krb5_error_code retval = KRB5KDC_ERR_PREAUTH_FAILED;
    krb5_data encoded_otp_req;
    char *otp = NULL;
    char *tokenid = NULL;
    int ret;
    krb5_keyblock *armor_key = NULL;
    krb5_data decrypted_data;
    struct otp_server_ctx *otp_ctx = (struct otp_server_ctx *) moddata;
    struct otp_req_ctx *req_ctx = NULL;
    krb5_timestamp now_sec, ts_sec;
    krb5_int32 now_usec, ts_usec;

    if (otp_ctx == NULL) {
        retval = EINVAL;
        SERVER_DEBUG(retval,
                     "No OTP server context found when verifying padata.");
        goto cleanup;
    }

    encoded_otp_req.length = data->length;
    encoded_otp_req.data = (char *) data->contents;

    retval = decode_krb5_pa_otp_req(&encoded_otp_req, &otp_req);
    if (retval != 0) {
        SERVER_DEBUG(retval, "Unable to decode OTP request.");
        goto cleanup;
    }

    if (otp_req->enc_data.ciphertext.data == NULL) {
        retval = EINVAL;
        SERVER_DEBUG(retval, "Missing encData in PA-OTP-REQUEST.");
        goto cleanup;
    }

    decrypted_data.length = otp_req->enc_data.ciphertext.length;
    decrypted_data.data = (char *) malloc(decrypted_data.length);
    if (decrypted_data.data == NULL) {
        retval = ENOMEM;
        goto cleanup;
    }

    armor_key = cb->fast_armor(context, rock);
    if (armor_key == NULL) {
        retval = EINVAL;
        SERVER_DEBUG(retval, "No armor key found when verifying padata.");
        goto cleanup;
    }

    retval = krb5_c_decrypt(context, armor_key, KRB5_KEYUSAGE_PA_OTP_REQUEST,
                            NULL, &otp_req->enc_data, &decrypted_data);
    if (retval != 0) {
        SERVER_DEBUG(retval, "Unable to decrypt encData in PA-OTP-REQUEST.");
        goto cleanup;
    }

    /* Verify the server nonce (PA-OTP-ENC-REQUEST).  */
    /* For some enctypes, the resulting output->length may include padding
       bytes, so we need < instead of != */
    if (decrypted_data.length < 8 + armor_key->length) {
        retval = EINVAL;
        SERVER_DEBUG(retval, "Invalid server nonce length.");
        goto cleanup;
    }
    if (krb5_us_timeofday(context, &now_sec, &now_usec)) {
        retval = EINVAL;
        SERVER_DEBUG(retval, "Unable to get current time.");
        goto cleanup;
    }

    /* FIXME: Use krb5int_check_clockskew() rather than using
       context->clockskew ourselves -- krb5_context is not public.
       Have to wait for it to become public though.  */
    ts_sec = ntohl(*((uint32_t *) (decrypted_data.data + armor_key->length)));
    ts_usec = ntohl(*((uint32_t *) (decrypted_data.data + armor_key->length + 4)));
    if (labs(now_sec - ts_sec) > context->clockskew
        || (labs(now_sec - ts_sec) == context->clockskew
            && ((now_sec > ts_sec && now_usec > ts_usec)
                || (now_sec < ts_sec && now_usec < ts_usec)))) {
        retval = KRB5KRB_AP_ERR_SKEW;
        SERVER_DEBUG(retval, "Bad timestamp in PA-OTP-ENC-REQUEST.");
        goto cleanup;
    }

    /* Get OTP and potential token id hint from user.  */
    otp = strndup(otp_req->otp_value.data, otp_req->otp_value.length);
    if (otp == NULL) {
        retval = ENOMEM;
        goto cleanup;
    }
    SERVER_DEBUG(0, "Got OTP [%s].", otp);
    if (otp_req->otp_token_id.data != NULL) {
        tokenid = strndup(otp_req->otp_token_id.data,
                          otp_req->otp_token_id.length);
        if (tokenid == NULL) {
            retval = ENOMEM;
            goto cleanup;
        }
        SERVER_DEBUG(0, "Got tokenid hint [%s].", tokenid);
    }

    /* Create request context.  */
    retval = otp_server_create_req_ctx(otp_ctx, rock, tokenid, cb, &req_ctx);
    if (retval != 0) {
        goto cleanup;
    }

    assert(req_ctx->method->ftable != NULL);
    assert(req_ctx->method->ftable->server_verify != NULL);
    ret = req_ctx->method->ftable->server_verify(req_ctx, otp);

    if (ret != 0) {
        retval = KRB5KDC_ERR_PREAUTH_FAILED;
        SERVER_DEBUG(retval, "Verification for [%s] failed with %d.",
                     req_ctx->token_id, ret);
        goto cleanup;
    }


    enc_tkt_reply->flags |= TKT_FLG_PRE_AUTH;
    enc_tkt_reply->flags |= TKT_FLG_HW_AUTH; /* FIXME: Let the OTP
                                                method decide about
                                                the HW flag?  */
    SERVER_DEBUG(0, "Verification succeeded for [%s].", req_ctx->token_id);

    /* Request context is consumed by the free_modreq_fn.  */
    retval = 0;

 cleanup:
    free(otp);
    otp = NULL;
    free(tokenid);
    tokenid = NULL;
    krb5_free_data_contents(context, &decrypted_data);
    if (otp_req != NULL) {
        krb5_free_data_contents(context, &otp_req->otp_value);
        krb5_free_data_contents(context, &otp_req->enc_data.ciphertext);
        free(otp_req);
    }
    if (retval != 0) {
        otp_server_free_req_ctx(&req_ctx);
        req_ctx = NULL;
    }
    (*respond)(arg, retval, (krb5_kdcpreauth_modreq)req_ctx, NULL, NULL);
}

static krb5_error_code
otp_server_return_padata(krb5_context context,
                         krb5_pa_data *padata,
                         krb5_data *req_pkt,
                         krb5_kdc_req *request,
                         krb5_kdc_rep *reply,
                         krb5_keyblock *encrypting_key,
                         krb5_pa_data **send_pa_out,
                         krb5_kdcpreauth_callbacks cb,
                         krb5_kdcpreauth_rock rock,
                         krb5_kdcpreauth_moddata moddata,
                         krb5_kdcpreauth_modreq modreq)
{
    krb5_keyblock *reply_key = NULL;
    krb5_error_code retval = -1;

    if (modreq == NULL) {
        SERVER_DEBUG(0, "Not handled by me.");
        return 0;
    }

    /* Replace the reply key with the FAST armor key.  */
    reply_key = cb->fast_armor(context, rock);
    if (reply_key == NULL) {
        return EINVAL;
        SERVER_DEBUG(retval, "No armor key found when returning padata.");
    }
    krb5_free_keyblock_contents(context, encrypting_key);
    retval = krb5_copy_keyblock_contents(context, reply_key, encrypting_key);
    if (retval != 0) {
        SERVER_DEBUG(retval, "Unable to copy reply key.");
        return retval;
    }

    return 0;
}

static krb5_preauthtype otp_server_supported_pa_types[] = {
    KRB5_PADATA_OTP_REQUEST,
    0
};

krb5_error_code
kdcpreauth_otp_initvt(krb5_context context, int maj_ver, int min_ver,
                      krb5_plugin_vtable vtable);

krb5_error_code
kdcpreauth_otp_initvt(krb5_context context, int maj_ver, int min_ver,
                      krb5_plugin_vtable vtable)
{
    krb5_kdcpreauth_vtable vt;

    if (maj_ver != 1) {
        return KRB5_PLUGIN_VER_NOTSUPP;
    }
    vt = (krb5_kdcpreauth_vtable) vtable;
    vt->name = "otp";
    vt->pa_type_list = otp_server_supported_pa_types;
    vt->init = otp_server_init;
    vt->fini = otp_server_fini;
    vt->flags = otp_server_get_flags;
    vt->edata = otp_server_get_edata;
    vt->verify = otp_server_verify_padata;
    vt->return_padata = otp_server_return_padata;
    vt->free_modreq = otp_server_free_modreq;

    return 0;
}
