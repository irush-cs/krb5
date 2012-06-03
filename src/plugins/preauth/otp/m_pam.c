/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Copyright 2011 School of Computer Science and Engineering, Hebrew University
 * of Jerusalem.  All rights reserved.
 * Author: Yair Yarom <irush@cs.huji.ac.il>
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

/*
 * FAST OTP plugin method using simplified PAM backend
 *
 * By default, the user is the principal name and the service is "krb5.<realm>"
 * (note that some pam implementation will put the service in lower case). If
 * the blob is available, then it contains <user>@<service> where both <user>
 * and <service> are optional (if no @, considered as service).
 */

#include <errno.h>
#include <security/pam_appl.h>
#include <k5-int.h>

#include "otp.h"
#include "m_pam.h"

int otp_pam_get_user_service(const struct otp_req_ctx *ctx,
                             char** user,
                             char** service);
int otp_pam_auth(char* user,
                 char* service,
                 char* rhost,
                 const char* password,
                 char** prompt);

struct otp_pam_ctx {
    int a;
};

typedef struct _otp_pam_conv_data {
    char* prompt;
    const char* password;
} otp_pam_conv_data;

static void
otp_pam_server_fini(void *method_context)
{
    struct otp_pam_ctx *ctx = method_context;
    free(ctx);
}

static int
otp_pam_verify_otp(const struct otp_req_ctx *otp_ctx, const char *pw)
{
    char* user = NULL;
    char* service = NULL;
    int retval = 0;
    SERVER_DEBUG(0, "[pam] otp_pam_verify_otp called.");

#if 0 /* in case otp_ctx->client will return... */
    if (otp_ctx->client == NULL) {
        SERVER_DEBUG(ENOENT, "[pam] don't know who the the client is.");
        return 1;
    }
#endif

    retval = otp_pam_get_user_service(otp_ctx, &user, &service);
    if (retval != 0) {
        return retval;
    }

    retval = otp_pam_auth(user, service, otp_ctx->from, pw, NULL);

    free(user);
    free(service);
    return retval;
}

static int
otp_pam_challenge(const struct otp_req_ctx *ctx,
                  krb5_otp_tokeninfo *tokeninfo)
{
    char* user = NULL;
    char* service = NULL;
    char* prompt = NULL;
    int retval = 0;

    SERVER_DEBUG(0, "[pam] otp_pam_challenge called.");

#if 0 /* in case otp_ctx->client will return... */
    if (ctx->client == NULL) {
        SERVER_DEBUG(ENOENT, "[pam] don't know who the the client is.");
        return 1;
    }
#endif

    retval = otp_pam_get_user_service(ctx, &user, &service);
    if (retval != 0) {
        return retval;
    }

    /* Should fail as password == NULL, so check if prompt != NULL */
    otp_pam_auth(user, service, ctx->from, NULL, &prompt);
    if (prompt == NULL) {
        retval = 1;
        goto out;
    }

    if (tokeninfo->otp_vendor.length != 0)
        free(tokeninfo->otp_vendor.data);

    tokeninfo->otp_vendor.data = prompt;
    tokeninfo->otp_vendor.length = strlen(prompt);

 out:
    free(user);
    free(service);
    return retval;
}

int
otp_pam_server_init(struct otp_server_ctx *otp_ctx,
                    get_config_func_t get_config,
                    struct otp_method_ftable **ftable,
                    void **method_context)
{
    struct otp_method_ftable *ft = NULL;
    struct otp_pam_ctx *ctx = NULL;
    int retval = -1;
    ft = calloc(1, sizeof(*ft));
    if (ft == NULL) {
        retval = ENOMEM;
        goto errout;
    }
    ft->server_fini = otp_pam_server_fini;
    ft->server_verify = otp_pam_verify_otp;
    ft->server_challenge = otp_pam_challenge;
    ctx = calloc(1, sizeof(*ctx));
    if (ctx == NULL) {
        retval = ENOMEM;
        goto errout;
    }

    *ftable = ft;
    *method_context = ctx;
    return 0;

 errout:
    if (ft != NULL)
        free(ft);
    if (ctx != NULL)
        free(ctx);
    return retval;
}



/**
 * pam stuff
 */

/** if succeeds, *user and *service will be allocated with the pam's username
    and service (according to either the blob or the principal). They should be
    freed after use */
int
otp_pam_get_user_service(const struct otp_req_ctx *ctx,
                         char** user,
                         char** service)
{
    //int len = 0;
    char* str = NULL;
    char* c;
    int retval = -1;
    int blobsize = ctx->blob ? strlen(ctx->blob) : 0;
    *user = NULL;
    *service = NULL;

    if (blobsize > 0) {
        /* will force a \0 terminated string */
        str = calloc(1, blobsize + 1);
        if (str == NULL) {
            retval = ENOMEM;
            goto error;
        }
        memcpy(str, ctx->blob, blobsize);
        c = strchr(str, '@');
        if (c != NULL) {
            *c++ = 0;
            if (str[0] != 0) {
                *user = strdup(str);
                if (*user == NULL) {
                    retval = ENOMEM;
                    goto error;
                }
            }
        } else {
            c = str;
        }

        if (c[0] != 0) {
            *service = strdup(c);
            if (*service == NULL) {
                retval = ENOMEM;
                goto error;
            }
        }
    }

    if (*user == NULL) {
#if 0 /* in case otp_ctx->client will return... */
        len = krb5_princ_name(ctx->krb5_context, ctx->client->princ)->length;
        if ((*user = calloc(1, len + 1)) == NULL) {
            retval = ENOMEM;
            goto error;
        }
        strncpy(*user,
                krb5_princ_name(ctx->krb5_context, ctx->client->princ)->data,
                len);
#else
        SERVER_DEBUG(ENOENT, "[pam] can't find pam user.");
        goto error;
#endif
    }

    if (*service == NULL) {
#if 0 /* in case otp_ctx->client will return... */
        len = krb5_princ_realm(ctx->krb5_context, ctx->client->princ)->length;
        if ((*service = calloc(1, len + 1 + 5)) == NULL) {
            retval = ENOMEM;
            goto error;
        }
        strcpy(*service, "krb5.");
        strncat(*service,
                krb5_princ_realm(ctx->krb5_context, ctx->client->princ)->data,
                len);
#else
        SERVER_DEBUG(ENOENT, "[pam] can't find pam service.");
        goto error;
#endif
    }

    SERVER_DEBUG(0, "[pam] got user: %s, service: %s, from %s.", *user, *service,
                 (blobsize > 0 ? "blob" : "principal"));

    if (str != NULL)
        free(str);
    return 0;

 error:
    if (str != NULL)
        free(str);
    if (*user != NULL) {
        free(*user);
        *user = NULL;
    }
    if (*service != NULL) {
        free(*service);
        *service = NULL;
    }
    return retval;
}

/** the pam conversation function. */
int
otp_pam_converse(int n,
                 const struct pam_message **msg,
                 struct pam_response **resp,
                 void *data);

int
otp_pam_converse(int n,
                     const struct pam_message **msg,
                     struct pam_response **resp,
                     void *data)
{
    struct pam_response *aresp;
    otp_pam_conv_data* pam_data = (otp_pam_conv_data*)data;
    int retval = PAM_SUCCESS;
    int i;

    if (n <= 0 || n > PAM_MAX_NUM_MSG)
        return (PAM_CONV_ERR);

    if ((aresp = calloc(n, sizeof *aresp)) == NULL)
        return (PAM_BUF_ERR);

    for (i = 0; i < n; ++i) {
        aresp[i].resp_retcode = 0;
        switch (msg[i]->msg_style) {
          case PAM_PROMPT_ECHO_OFF:
          case PAM_PROMPT_ECHO_ON:
              /* If no password, get the prompt. Otherwise, set the password. */
              if (pam_data->password == NULL) {
                  pam_data->prompt = strdup(msg[i]->msg);
                  if (pam_data->prompt == NULL)
                      goto buferr;
                  goto converr;
              } else {
                  aresp[i].resp = strdup(pam_data->password);
                  if (aresp[i].resp == NULL)
                      goto buferr;
              }
              break;

          case PAM_ERROR_MSG:
          case PAM_TEXT_INFO:
              goto converr;

        default:
            break;
        }
    }

    *resp = aresp;
    return (PAM_SUCCESS);

 converr:
    retval = PAM_CONV_ERR;
    goto failure;
 buferr:
    retval = PAM_BUF_ERR;
 failure:
    for (i = 0; i < n; i++) {
        if (aresp[i].resp)
            free(aresp[i].resp);
    }
    free(aresp);
    return retval;
}

/* Returns the pam result (PAM_SUCCESS on success) */
int
otp_pam_auth(char* user, char* service, char* rhost, const char* password, char** prompt)
{
    struct pam_conv conv;
    otp_pam_conv_data data;
    pam_handle_t* pamh = NULL;
    int pamres = 0;
    int i;

    memset(&data, 0, sizeof(data));
    if (password != NULL) {
        data.password = password;
    }

    conv.conv = &otp_pam_converse;
    conv.appdata_ptr = &data;

    if ((pamres = pam_start(service, user, &conv, &pamh)) != PAM_SUCCESS) {
        SERVER_DEBUG(0, "[pam] pam_start(%s, %s, &conv, &pamh) = %i (%s)\n",
                     service, user, pamres, pam_strerror(pamh, pamres));
        pam_end(pamh, pamres);
        return pamres;
    }

    if ((pamres = pam_set_item(pamh, PAM_RHOST, rhost)) != PAM_SUCCESS) {
        SERVER_DEBUG(0, "[pam] pam_set_item(PAM_RHOST, %s) = %i (%s)\n",
                     rhost, pamres, pam_strerror(pamh, pamres));
    }

    pamres = pam_authenticate(pamh, PAM_SILENT | PAM_DISALLOW_NULL_AUTHTOK);

    if (data.prompt != NULL && prompt != NULL) {
        *prompt = data.prompt;
        data.prompt = NULL;
        for (i = strlen(*prompt) - 1; i >= 0; i--) {
            switch ((*prompt)[i]) {
              case ' ':
              case '\t':
              case ':':
              case '\n':
                  (*prompt)[i] = 0;
                  break;
              default:
                  i = -1;
            }
        }
    }
    if (data.prompt != NULL)
        free(data.prompt);

    pam_end(pamh, pamres);
    return pamres;
}
