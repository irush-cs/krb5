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

  otp_force_address option can be used (in libdefaults or the realm section) to
  force a single address in the replied ticket which is the connection address.

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
#include "../asn1/PA-OTP-CHALLENGE.h"
#include "../asn1/PA-OTP-REQUEST.h"
#include "../asn1/PA-OTP-ENC-REQUEST.h"

/* FIXME: Belong in krb5.hin.  */
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

#include "../otp.h"
#if defined (OTP_PREAUTH_ENABLE_BASICAUTH)
#include "m_basicauth.h"
#endif
#if defined (OTP_PREAUTH_ENABLE_YKCLIENT)
#include "m_ykclient.h"
#endif
#if defined (OTP_PREAUTH_ENABLE_PAM)
#include "m_pam.h"
#endif

/* Configured OTP methods.  */
struct otp_method otp_methods[] = {
#if defined (OTP_PREAUTH_ENABLE_BASICAUTH)
    {"basicauth", otp_basicauth_server_init, 0, NULL, NULL},
#endif
#if defined (OTP_PREAUTH_ENABLE_YKCLIENT)
    {"ykclient", otp_ykclient_server_init, 0, NULL, NULL},
#endif
#if defined (OTP_PREAUTH_ENABLE_PAM)
    {"pam", otp_pam_server_init, 0, NULL, NULL},
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
otp_server_free_req_ctx(struct otp_server_ctx* ctx, struct otp_req_ctx **request)
{
    if (*request == NULL)
        return;
    free((*request)->token_id);
    free((*request)->blob);
    free((*request)->from);
    krb5_free_addresses(ctx->krb5_context,(*request)->addrl);
    free(*request);
    *request = NULL;
}

static void
otp_server_free_modreq(krb5_context context,
                       krb5_kdcpreauth_moddata moddata,
                       krb5_kdcpreauth_modreq modreq)
{
    otp_server_free_req_ctx((struct otp_server_ctx *) moddata, (struct otp_req_ctx **) &modreq);
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
        otp_server_free_req_ctx(ctx, &req);
        return retval;
    }

    if (((req->addrl = calloc(2, sizeof(*req->addrl))) == NULL) ||
        (krb5_copy_addr(ctx->krb5_context, rock->from->address, &(req->addrl[0])) != 0)) {
        otp_server_free_req_ctx(ctx, &req);
        return ENOMEM;
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
    PA_OTP_CHALLENGE_t* otp_challenge = NULL;
    OTP_TOKENINFO_t* otp_tokeninfo = NULL;
    krb5_data encoded_otp_challenge;
    struct otp_server_ctx *otp_ctx = (struct otp_server_ctx *) moddata;
    struct otp_req_ctx *otp_req = NULL;
    krb5_timestamp ts;
    krb5_data nonce;
    int i;

    assert(otp_ctx != NULL);
    memset(&encoded_otp_challenge, 0, sizeof(encoded_otp_challenge));

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

    otp_challenge = calloc(1, sizeof(*otp_challenge));
    if (otp_challenge == NULL) {
        (*respond)(arg, ENOMEM, NULL);
        goto cleanup;
    }

    otp_challenge->nonce.size = armor_key->length + sizeof(ts);
    otp_challenge->nonce.buf = malloc(otp_challenge->nonce.size);
    if (otp_challenge->nonce.buf == NULL) {
        (*respond)(arg, ENOMEM, NULL);
        goto cleanup;
    }
    nonce.length = otp_challenge->nonce.size;
    nonce.data = (void*)otp_challenge->nonce.buf;
    retval = krb5_c_random_make_octets(context, &nonce);
    if (retval != 0) {
        SERVER_DEBUG(retval, "Unable to create random data for nonce.");
        (*respond)(arg, retval, NULL);
        goto cleanup;
    }
    retval = krb5_timeofday(context, &ts);
    if (retval != 0) {
        SERVER_DEBUG(retval, "Unable to get current time.");
        (*respond)(arg, retval, NULL);
        goto cleanup;
    }
    *((uint32_t *) (otp_challenge->nonce.buf + armor_key->length)) =
        htonl(ts);

    otp_tokeninfo = calloc(1, sizeof(*otp_tokeninfo));
    if (otp_tokeninfo == NULL) {
        (*respond)(arg, ENOMEM, NULL);
        goto cleanup;        
    }
    ASN_SEQUENCE_ADD(&otp_challenge->otp_tokenInfo, otp_tokeninfo);

    /* Get the otp_service */
    otp_challenge->otp_service = calloc(1, sizeof(*otp_challenge->otp_service));
    if (otp_challenge->otp_service == NULL) {
        (*respond)(arg, ENOMEM, NULL);
        goto cleanup;
    }
    otp_challenge->otp_service->buf = (void*)otp_profile_get_service(context->profile, krb5_princ_realm(context, request->client));
    if (otp_challenge->otp_service->buf != NULL)
        otp_challenge->otp_service->size = strlen(otp_challenge->otp_service->buf);

    retval = otp_server_create_req_ctx(otp_ctx, rock, NULL, cb, &otp_req);
    if (retval != 0) {
        SERVER_DEBUG(retval, "Unable to create request context for edata.");
        (*respond)(arg, retval, NULL);
        goto cleanup;
    }

    /* Let the method set up a challenge (the tokeninfo) */
    if (otp_req->method->ftable->server_challenge) {
        retval = otp_req->method->ftable->server_challenge(otp_req,
                                                           otp_challenge->otp_tokenInfo.list.array[0]);
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
    // FIXME: 
    otp_challenge->otp_tokenInfo.list.array[0]->flags.buf = calloc(1, 4);
    otp_challenge->otp_tokenInfo.list.array[0]->flags.size = 4;
    

    /* Encode challenge.  */
    //retval = encode_krb5_pa_otp_challenge(&otp_challenge,
    //                                      &encoded_otp_challenge);
    // FIXME: check errors
    der_encode(&asn_DEF_PA_OTP_CHALLENGE, otp_challenge, otp_encoder, &encoded_otp_challenge);
    
    if (retval != 0) {
        SERVER_DEBUG(retval, "Unable to encode challenge.");
        (*respond)(arg, retval, NULL);
        goto cleanup;
    }

    pa->pa_type = KRB5_PADATA_OTP_CHALLENGE;
    pa->length = encoded_otp_challenge.length;
    pa->contents = malloc(pa->length);
    if (pa->contents == NULL) {
        retval = ENOMEM;
        goto cleanup;
    }
    memcpy(pa->contents, encoded_otp_challenge.data, pa->length);
    (*respond)(arg, retval, pa);

 cleanup:
    krb5_free_data_contents(context, &encoded_otp_challenge);
    if (otp_req != NULL)
        otp_server_free_req_ctx(otp_ctx, &otp_req);
    if (otp_challenge != NULL) {
        if (otp_challenge->nonce.buf != NULL)
            free(otp_challenge->nonce.buf);
        if (otp_challenge->otp_service != NULL) {
            if (otp_challenge->otp_service->buf != NULL)
                free(otp_challenge->otp_service->buf);
            free(otp_challenge->otp_service);
        }
        for (i = 0; i < otp_challenge->otp_tokenInfo.list.count; i++) {
            if (otp_challenge->otp_tokenInfo.list.array[i]->flags.buf)
                free(otp_challenge->otp_tokenInfo.list.array[i]->flags.buf);
            asn_sequence_del(&otp_challenge->otp_tokenInfo, 0, 1);
        }
        // TODO: with a free function can free the tokenInfo
        asn_sequence_empty(&otp_challenge->otp_tokenInfo);
        free(otp_challenge);
    }
    if (otp_tokeninfo != NULL) {
        if (otp_tokeninfo->otp_vendor != NULL)
            free(otp_tokeninfo->otp_vendor);
        free(otp_tokeninfo);
    }
    if (retval != 0 && pa != NULL)
        free(pa);
}

krb5_error_code
nonce_verify(struct otp_server_ctx*, krb5_keyblock*, krb5_data*);

/*
 * Stolen from authhub (https://fedorahosted.org/AuthHub/)
 */
krb5_error_code
nonce_verify(struct otp_server_ctx *ctx, krb5_keyblock *armor_key, krb5_data *data)
{
    krb5_error_code retval = EINVAL;
    krb5_timestamp ts;
    PA_OTP_ENC_REQUEST_t *encreq = NULL;
    asn_dec_rval_t rval;

    if (!ctx || !armor_key || !data)
        goto out;

    /* Decode the PA-OTP-ENC-REQUEST structure */
    rval = ber_decode(0, &asn_DEF_PA_OTP_ENC_REQUEST, (void**)&encreq, data->data, data->length);
    if (rval.code != RC_OK)
        goto out;

    /* Make sure the nonce is exactly the same size as the one generated */
    if (encreq->nonce.size != armor_key->length + sizeof(krb5_timestamp))
        goto out;

    /* Check to make sure the timestamp at the end is still valid */
    ts = ntohl(((krb5_timestamp*)(encreq->nonce.buf + armor_key->length))[0]);
    retval = krb5_check_clockskew(ctx->krb5_context, ts);

 out:
    asn_DEF_PA_OTP_ENC_REQUEST.free_struct(&asn_DEF_PA_OTP_ENC_REQUEST, encreq, 0);
    return retval;
}

// /*
//  * Also stolen from authhub
//  */
// krb5_error_code
// timestamp_verify(krb5_context ctx, const char *data, unsigned int len)
// {
//     krb5_error_code retval = EINVAL;
//     PA_ENC_TS_ENC_t *et = NULL;
//     krb5_timestamp time;
//     struct tm zero(t);
// 
//     if (!ctx || !data)
//         goto egress;
// 
//     /* Decode the PA-ENC-TS-ENC structure */
//     et = int_ber_decode(PA_ENC_TS_ENC, data, len);
//     if (!et)
//         goto egress;
// 
//     /* Get the timestamp */
//     asn_GT2time(&et->patimestamp, &t, 0);
//     time = mktime(&t);
//     if (time < 0)
//         goto egress;
// 
//     /* Check the clockskew */
//     retval = krb5_check_clockskew(ctx, time);
// 
//  egress:
//     asn_DEF_PA_ENC_TS_ENC.free_struct(&asn_DEF_PA_ENC_TS_ENC, et, 0);
//     return retval;
// }

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
    PA_OTP_REQUEST_t *otp_req = NULL;
    krb5_error_code retval = KRB5KDC_ERR_PREAUTH_FAILED;
    krb5_data encoded_otp_req;
    char *otp = NULL;
    char *tokenid = NULL;
    int ret;
    krb5_keyblock *armor_key = NULL;
    krb5_enc_data encrypted_data;
    krb5_data decrypted_data;
    struct otp_server_ctx *otp_ctx = (struct otp_server_ctx *) moddata;
    struct otp_req_ctx *req_ctx = NULL;
    krb5_timestamp now_sec, ts_sec;
    krb5_int32 now_usec, ts_usec;
    long int kvno;
    asn_dec_rval_t drval;

    memset(&decrypted_data, 0, sizeof(decrypted_data));
    
    if (otp_ctx == NULL) {
        retval = EINVAL;
        SERVER_DEBUG(retval,
                     "No OTP server context found when verifying padata.");
        goto cleanup;
    }

    encoded_otp_req.length = data->length;
    encoded_otp_req.data = (char *) data->contents;

    drval = ber_decode(0, &asn_DEF_PA_OTP_REQUEST, (void**)&otp_req, encoded_otp_req.data, encoded_otp_req.length);
    if (drval.code != RC_OK) {
        SERVER_DEBUG(retval, "Unable to decode OTP request.");
        goto cleanup;
    }

    if (otp_req->encData.cipher.buf == NULL) {
        retval = EINVAL;
        SERVER_DEBUG(retval, "Missing encData in PA-OTP-REQUEST.");
        goto cleanup;
    }

    decrypted_data.length = otp_req->encData.cipher.size;
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

    // FIXME, verify casting is correct, check errors
    encrypted_data.enctype = otp_req->encData.etype;
    asn_INTEGER2long(otp_req->encData.kvno, &kvno);
    encrypted_data.kvno = kvno;
    encrypted_data.ciphertext.data = (void*)otp_req->encData.cipher.buf;
    encrypted_data.ciphertext.length = otp_req->encData.cipher.size;
    retval = krb5_c_decrypt(context, armor_key, KRB5_KEYUSAGE_PA_OTP_REQUEST,
                            NULL, &encrypted_data, &decrypted_data);
    if (retval != 0) {
        SERVER_DEBUG(retval, "Unable to decrypt encData in PA-OTP-REQUEST.");
        goto cleanup;
    }

    /* Verify the server nonce (PA-OTP-ENC-REQUEST).  */
    /* For some enctypes, the resulting output->length may include padding
       bytes, so we need < instead of != */
    //if (decrypted_data.length < 8 + armor_key->length) {
    //    retval = EINVAL;
    //    SERVER_DEBUG(retval, "Invalid server nonce length.");
    //    goto cleanup;
    //}
    //if (krb5_us_timeofday(context, &now_sec, &now_usec)) {
    //    retval = EINVAL;
    //    SERVER_DEBUG(retval, "Unable to get current time.");
    //    goto cleanup;
    //}

    /* Verify the nonce or timestamp */
    retval = nonce_verify(otp_ctx, armor_key, &decrypted_data);
    // FIXME, use timestamp if failed
    //if (retval != 0)
    //    retval = timestamp_verify(context, tmp, size);
    //free(tmp);
    if (retval != 0) {

    /* FIXME: Use krb5int_check_clockskew() rather than using
       context->clockskew ourselves -- krb5_context is not public.
       Have to wait for it to become public though.  */
        //ts_sec = ntohl(*((uint32_t *) (decrypted_data.data + armor_key->length)));
        //ts_usec = ntohl(*((uint32_t *) (decrypted_data.data + armor_key->length + 4)));
        //if (labs(now_sec - ts_sec) > context->clockskew
        //|| (labs(now_sec - ts_sec) == context->clockskew
        //&& ((now_sec > ts_sec && now_usec > ts_usec)
        //|| (now_sec < ts_sec && now_usec < ts_usec)))) {
        retval = KRB5KRB_AP_ERR_SKEW;
        SERVER_DEBUG(retval, "Unable to verify nonce or timestamp.");
        goto cleanup;
    }

    /* Get OTP and potential token id hint from user.  */
    otp = strndup(otp_req->otp_value->buf, otp_req->otp_value->size);
    if (otp == NULL) {
        retval = ENOMEM;
        goto cleanup;
    }
    /* dangerous with regular password instead of otp, even if just for debug */
    // SERVER_DEBUG(0, "Got OTP [%s].", otp);
    if (otp_req->otp_tokenID != NULL && otp_req->otp_tokenID->buf != NULL) {
        tokenid = strndup(otp_req->otp_tokenID->buf,
                          otp_req->otp_tokenID->size);
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

    /* Keep just one address */
    //if (enc_tkt_reply->caddrs) {
    //    krb5_address **temp;
    //    for (temp = enc_tkt_reply->caddrs; *temp; temp++) {}
    //    while (temp != enc_tkt_reply->caddrs) {
    //        krb5_free_address(otp_ctx->krb5_context, temp);
    //        *temp = 0;
    //        temp--;
    //    }
    //}
    if (otp_profile_get_force_address(context->profile, krb5_princ_realm(ctx->krb5_context, request->client)))
        enc_tkt_reply->caddrs = req_ctx->addrl;

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
    asn_DEF_PA_OTP_REQUEST.free_struct(&asn_DEF_PA_OTP_REQUEST, otp_req, 0);
    //FIXME, free otp_req
    //if (otp_req != NULL) {
    //    krb5_free_data_contents(context, &otp_req->otp_value);
    //    krb5_free_data_contents(context, &otp_req->encData.cipher);
    //    free(otp_req);
    //}
    if (retval != 0) {
        otp_server_free_req_ctx(otp_ctx, &req_ctx);
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
