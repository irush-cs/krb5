/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Copyright 2012 School of Computer Science and Engineering, Hebrew University
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

#include "otp.h"

/*
 * XXX: Copied from src/util/profile/prof_get.c
 */

static const char *const conf_yes[] = {
    "y", "yes", "true", "t", "1", "on",
    0,
};

static const char *const conf_no[] = {
    "n", "no", "false", "nil", "0", "off",
    0,
};

static errcode_t
profile_parse_boolean(const char *s, int *ret_boolean)
{
    const char *const *p;

    if (ret_boolean == NULL)
        return PROF_EINVAL;

    for(p=conf_yes; *p; p++) {
        if (!strcasecmp(*p,s)) {
            *ret_boolean = 1;
            return 0;
        }
    }

    for(p=conf_no; *p; p++) {
        if (!strcasecmp(*p,s)) {
            *ret_boolean = 0;
            return 0;
        }
    }

    return PROF_BAD_BOOLEAN;
}
/*
 * XXX: End copy
 */

long
otp_profile_get_hidden(profile_t profile,
                       const char *prompt,
                       const krb5_data *realm) {

    const char *names[5][5];
    krb5_error_code retval;
    char **nameval = NULL;
    int result = 0;
    int n_names = 0;
    int i;
    char realmstr[1024];

    if (realm != NULL) {
        if (realm->length < sizeof(realmstr)) {
            strncpy(realmstr, realm->data, realm->length);
            realmstr[realm->length] = '\0';
        }
    } else {
        realmstr[0] = 0;
    }
    
    /*
      realms -> <realm> -> otp_hidden -> <prompt>
      realms -> <realm> -> otp_hidden
      libdefaults -> otp_hidden -> <prompt>
      libdefaults -> otp_hidden
    */

    if (realmstr[0] != 0) {
        if (prompt != NULL) {
            names[n_names][0] = KRB5_CONF_REALMS;
            names[n_names][1] = realmstr;
            names[n_names][2] = "otp_hidden";
            names[n_names][3] = prompt;
            names[n_names][4] = 0;
            n_names++;
        }
        names[n_names][0] = KRB5_CONF_REALMS;
        names[n_names][1] = realmstr;
        names[n_names][2] = "otp_hidden";
        names[n_names][3] = 0;
        n_names++;
    }
    if (prompt != NULL) {
        names[n_names][0] = KRB5_CONF_LIBDEFAULTS;
        names[n_names][1] = "otp_hidden";
        names[n_names][2] = prompt;
        names[n_names][3] = 0;
        n_names++;
    }
    names[n_names][0] = KRB5_CONF_LIBDEFAULTS;
    names[n_names][1] = "otp_hidden";
    names[n_names][2] = 0;
    n_names++;

    for (i = 0; i < n_names; i++) {
        retval = profile_get_values(profile, names[i], &nameval);

        if (retval == 0 && nameval) {
            if (nameval[0] && profile_parse_boolean(nameval[0], &result) == 0) {
                profile_free_list(nameval);                
                break;
            }
            profile_free_list(nameval);
        }
    }

    return result;
}


char*
otp_profile_get_service(profile_t profile,
                        const krb5_data *realm) {

    const char *names[2][5];
    krb5_error_code retval;
    char **nameval = NULL;
    char* result = NULL;
    int n_names = 0;
    int i;
    char realmstr[1024];

    if (realm != NULL) {
        if (realm->length < sizeof(realmstr)) {
            strncpy(realmstr, realm->data, realm->length);
            realmstr[realm->length] = '\0';
        }
    } else {
        realmstr[0] = 0;
    }

    /*
      realms -> <realm> -> otp_service
      libdefaults -> otp_service
    */

    if (realmstr[0] != 0) {
        names[n_names][0] = KRB5_CONF_REALMS;
        names[n_names][1] = realmstr;
        names[n_names][2] = "otp_service";
        names[n_names][3] = 0;
        n_names++;
    }
    names[n_names][0] = KRB5_CONF_LIBDEFAULTS;
    names[n_names][1] = "otp_service";
    names[n_names][2] = 0;
    n_names++;

    for (i = 0; i < n_names; i++) {
        retval = profile_get_values(profile, names[i], &nameval);

        if (retval == 0 && nameval) {
            if (nameval[0]) {
                result = strdup(nameval[0]);
                profile_free_list(nameval);
                break;
            }
            profile_free_list(nameval);
        }
    }

    return result;
}

long
otp_profile_get_force_address(profile_t profile,
                              const krb5_data *realm) {
    const char *names[2][5];
    krb5_error_code retval;
    char **nameval = NULL;
    int result = 0;
    int n_names = 0;
    int i;
    char realmstr[1024];

    if (realm != NULL) {
        if (realm->length < sizeof(realmstr)) {
            strncpy(realmstr, realm->data, realm->length);
            realmstr[realm->length] = '\0';
        }
    } else {
        realmstr[0] = 0;
    }

    /*
      realms -> <realm> -> force_address
      libdefaults -> force_address
    */

    if (realmstr[0] != 0) {
        names[n_names][0] = KRB5_CONF_REALMS;
        names[n_names][1] = realmstr;
        names[n_names][2] = "otp_force_address";
        names[n_names][3] = 0;
        n_names++;
    }
    names[n_names][0] = KRB5_CONF_LIBDEFAULTS;
    names[n_names][1] = "otp_force_address";
    names[n_names][2] = 0;
    n_names++;

    for (i = 0; i < n_names; i++) {
        retval = profile_get_values(profile, names[i], &nameval);

        if (retval == 0 && nameval) {
            if (nameval[0] && profile_parse_boolean(nameval[0], &result) == 0) {
                profile_free_list(nameval);                
                break;
            }
            profile_free_list(nameval);
        }
    }

    return result;
}
