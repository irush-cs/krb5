/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/krb5/os/t_trace.c - Test harness for trace.c */
/*
 * Copyright (C) 2012 by the Massachusetts Institute of Technology.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include "port-sockets.h"
#include <com_err.h>

#define TEST
#include "k5-int.h"
#include "cm.h"

const char *prog;

static void
kfatal (krb5_error_code err)
{
    com_err (prog, err, "- exiting");
    exit (1);
}

int
main (int argc, char *argv[])
{
    char *p;
    krb5_context ctx;
    krb5_error_code err;
    int i = -1;
    long ln = -2;
    size_t s = 0;
    char *str = "example.data";
    krb5_octet *oct = (krb5_octet *) str;
    unsigned int oct_length = strlen(str);
    struct conn_state conn;
    struct sockaddr_in *addr_in;
    krb5_data data;
    struct krb5_key_st key;
    krb5_checksum checksum;
    krb5_principal_data principal_data, principal_data2;
    krb5_principal princ = &principal_data;
    krb5_pa_data padata, padata2, **padatap;
    krb5_enctype enctypes[4] = {
        ENCTYPE_DES3_CBC_SHA, ENCTYPE_ARCFOUR_HMAC_EXP, ENCTYPE_UNKNOWN,
        ENCTYPE_NULL};
    krb5_ccache ccache;
    krb5_keytab keytab;
    krb5_creds creds;

    p = strrchr (argv[0], '/');
    if (p)
        prog = p+1;
    else
        prog = argv[0];

    if (argc != 1) {
        fprintf (stderr, "%s: usage: %s\n", prog, prog);
        return 1;
    }

    err = krb5_init_context (&ctx);
    if (err)
        kfatal (err);

    krb5int_trace(NULL, NULL);
    TRACE(ctx, "simple format");

    TRACE(ctx, "int, in decimal: {int}", i);
    TRACE(ctx, "long, in decimal: {long}", ln);

    TRACE(ctx, "const char *, display as C string: {str}", str);
    s = strlen(str);
    TRACE(ctx, "size_t and const char *, as a counted string: {lenstr}",
          s, str);
    TRACE(ctx, "size_t and const char *, as a counted string: {lenstr}",
          1, NULL);
    TRACE(ctx, "size_t and const char *, as hex bytes: {hexlenstr}",
          s, str);
    TRACE(ctx, "size_t and const char *, as hex bytes: {hexlenstr}",
          1, NULL);
    TRACE(ctx, "size_t and const char *, as four-character hex hash: "
          "{hashlenstr}", s, str);
    TRACE(ctx, "size_t and const char *, as four-character hex hash: "
          "{hashlenstr}", 1, NULL);

    conn.socktype = SOCK_STREAM;
    addr_in = (struct sockaddr_in *) &conn.addr;
    addr_in->sin_family = AF_INET;
    addr_in->sin_addr.s_addr = INADDR_ANY;
    addr_in->sin_port = htons(88);
    TRACE(ctx, "struct conn_state *, show socket type, address, port: "
          "{connstate}", &conn);
    conn.socktype = SOCK_DGRAM;
    TRACE(ctx, "struct conn_state *, show socket type, address, port: "
          "{connstate}", &conn);
    conn.socktype = SOCK_RDM;
    addr_in->sin_family = AF_UNSPEC;
    TRACE(ctx, "struct conn_state *, show socket type, address, port: "
          "{connstate}", &conn);
    conn.family = AF_UNSPEC;
    TRACE(ctx, "struct conn_state *, show socket type, address, port: "
          "{connstate}", &conn);

    data.magic = 0;
    data.length = strlen(str);
    data.data = str;
    TRACE(ctx, "krb5_data *, display as counted string: {data}", &data);
    TRACE(ctx, "krb5_data *, display as counted string: {data}", NULL);
    TRACE(ctx, "krb5_data *, display as hex bytes: {hexdata}", &data);
    TRACE(ctx, "krb5_data *, display as hex bytes: {hexdata}", NULL);

    TRACE(ctx, "int, display as number/errorstring: {errno}", 0);
    TRACE(ctx, "int, display as number/errorstring: {errno}", 1);
    TRACE(ctx, "krb5_error_code, display as number/errorstring: {kerr}", 0);

    key.keyblock.magic = 0;
    key.keyblock.enctype = ENCTYPE_UNKNOWN;
    key.keyblock.length = strlen(str);
    key.keyblock.contents = (krb5_octet *)str;
    key.refcount = 0;
    key.derived = NULL;
    key.cache = NULL;
    TRACE(ctx, "const krb5_keyblock *, display enctype and hash of key: "
          "{keyblock}", &key.keyblock);
    TRACE(ctx, "const krb5_keyblock *, display enctype and hash of key: "
          "{keyblock}", NULL);
    TRACE(ctx, "krb5_key, display enctype and hash of key: {key}", &key);
    TRACE(ctx, "krb5_key, display enctype and hash of key: {key}", NULL);

    checksum.magic = 0;
    checksum.checksum_type = -1;
    checksum.length = oct_length;
    checksum.contents = oct;
    TRACE(ctx, "const krb5_checksum *, display cksumtype and hex checksum: "
          "{cksum}", &checksum);

    principal_data.magic = 0;
    principal_data.realm.magic = 0;
    principal_data.realm.data = "ATHENA.MIT.EDU";
    principal_data.realm.length = strlen(principal_data.realm.data);
    principal_data.data = &data;
    principal_data.length = 0;
    principal_data.type = KRB5_NT_UNKNOWN;
    TRACE(ctx, "krb5_principal, unparse and display: {princ}", princ);
    TRACE(ctx, "int, krb5_principal type: {ptype}", KRB5_NT_UNKNOWN);
    TRACE(ctx, "int, krb5_principal type: {ptype}", KRB5_NT_PRINCIPAL);
    TRACE(ctx, "int, krb5_principal type: {ptype}", KRB5_NT_SRV_INST);
    TRACE(ctx, "int, krb5_principal type: {ptype}", KRB5_NT_SRV_HST);
    TRACE(ctx, "int, krb5_principal type: {ptype}", KRB5_NT_SRV_XHST);
    TRACE(ctx, "int, krb5_principal type: {ptype}", KRB5_NT_UID);
    TRACE(ctx, "int, krb5_principal type: {ptype}", KRB5_NT_X500_PRINCIPAL);
    TRACE(ctx, "int, krb5_principal type: {ptype}", KRB5_NT_SMTP_NAME);
    TRACE(ctx, "int, krb5_principal type: {ptype}",
          KRB5_NT_ENTERPRISE_PRINCIPAL);
    TRACE(ctx, "int, krb5_principal type: {ptype}", KRB5_NT_WELLKNOWN);
    TRACE(ctx, "int, krb5_principal type: {ptype}", KRB5_NT_MS_PRINCIPAL);
    TRACE(ctx, "int, krb5_principal type: {ptype}",
          KRB5_NT_MS_PRINCIPAL_AND_ID);
    TRACE(ctx, "int, krb5_principal type: {ptype}",
          KRB5_NT_ENT_PRINCIPAL_AND_ID);
    TRACE(ctx, "int, krb5_principal type: {ptype}", -1);

    padatap = malloc(sizeof(krb5_pa_data *) * 3);
    padatap[0] = &padata;
    memcpy(&padata2, &padata, sizeof(padata));
    padatap[1] = &padata2;
    padatap[2] = NULL;
    padata.magic = 0;
    padata.pa_type = KRB5_PADATA_NONE;
    padata.length = oct_length;
    padata.contents = oct;
    TRACE(ctx, "krb5_pa_data **, display list of padata type numbers: "
          "{patypes}", padatap);
    TRACE(ctx, "krb5_pa_data **, display list of padata type numbers: "
          "{patypes}", NULL);
    free(padatap);
    padatap = NULL;

    TRACE(ctx, "krb5_enctype, display shortest name of enctype: {etype}",
          ENCTYPE_DES_CBC_CRC);
    TRACE(ctx, "krb5_enctype *, display list of enctypes: {etypes}", enctypes);
    TRACE(ctx, "krb5_enctype *, display list of enctypes: {etypes}", NULL);

    err = krb5_cc_default(ctx, &ccache);
    TRACE(ctx, "krb5_ccache, display type:name: {ccache}", ccache);
    krb5_cc_close(ctx, ccache);

    err = krb5_kt_default(ctx, &keytab);
    TRACE(ctx, "krb5_keytab, display name: {keytab}", keytab);
    krb5_kt_close(ctx, keytab);

    creds.magic = 0;
    creds.client = &principal_data;
    memcpy(&principal_data2, &principal_data, sizeof(principal_data));
    principal_data2.realm.data = "ZEUS.MIT.EDU";
    principal_data2.realm.length = strlen(principal_data2.realm.data);
    creds.server = &principal_data2;
    memcpy(&creds.keyblock, &key.keyblock, sizeof(creds.keyblock));
    creds.times.authtime = 0;
    creds.times.starttime = 1;
    creds.times.endtime = 2;
    creds.times.renew_till = 3;
    creds.is_skey = FALSE;
    creds.ticket_flags = 0;
    creds.addresses = NULL;
    creds.ticket.magic = 0;
    creds.ticket.length = strlen(str);
    creds.ticket.data = str;
    creds.second_ticket.magic = 0;
    creds.second_ticket.length = strlen(str);
    creds.second_ticket.data = str;
    creds.authdata = NULL;
    TRACE(ctx, "krb5_creds *, display clientprinc -> serverprinc: {creds}",
          &creds);

    krb5_free_context(ctx);
    return 0;
}
