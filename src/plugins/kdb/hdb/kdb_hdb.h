#ifndef KRB5_KDB_HDB_H
#define KRB5_KDB_HDB_H

#include "k5-plugin.h"
#include "hdb.h"
#include "windc_plugin.h"

typedef krb5_int32 heim_error_code;

typedef struct _kh_db_context {
    k5_mutex_t *lock;
    heim_context hcontext;
    HDB *hdb;

    /* libkrb5 APIs */
    struct plugin_file_handle *libkrb5;
    heim_error_code (*heim_init_context)(heim_context *);
    void (*heim_free_context)(heim_context);
    void (*heim_free_principal)(heim_context, Principal *);
    heim_error_code (*heim_free_addresses)(heim_context, HostAddresses *);
    void (*heim_pac_free)(heim_context, heim_pac);
    heim_error_code (*heim_pac_parse)(heim_context, const void *,
                                      size_t, heim_pac *);
    heim_error_code (*heim_pac_verify)(heim_context, const heim_pac,
                                       time_t, const Principal *,
                                       const EncryptionKey *,
                                       const EncryptionKey *);
    heim_error_code (*heim_pac_sign)(heim_context, heim_pac,
                                     time_t, Principal *,
                                     const EncryptionKey *,
                                     const EncryptionKey *,
                                     heim_octet_string *);

    /* libhdb APIs */
    struct plugin_file_handle *libhdb;
    heim_error_code (*hdb_create)(heim_context, HDB **, const char *);
    heim_error_code (*hdb_seal_key)(heim_context, HDB *, Key *);
    heim_error_code (*hdb_unseal_key)(heim_context, HDB *, Key *);
    void (*hdb_free_entry)(heim_context, hdb_entry_ex *);

    /* widdc SPIs */
    struct plugin_dir_handle windc_plugins;
    krb5plugin_windc_ftable *windc;
    void *windc_ctx;
} kh_db_context;

#define KH_DB_CONTEXT(_context)    \
    ((kh_db_context *)(_context)->dal_handle->db_context)

#define KH_DB_ENTRY(_entry)         \
    ((hdb_entry_ex *)(_entry)->e_data)

/* kdb_hdb.c */

krb5_error_code
kh_map_error(heim_error_code code);

krb5_error_code
kh_marshal_Principal(krb5_context context,
                     krb5_const_principal kprinc,
                     Principal **out_hprinc);

void
kh_free_Principal(krb5_context context,
                  Principal *principal);

void
kh_free_HostAddresses(krb5_context context,
                      HostAddresses *addrs);

krb5_error_code
kh_get_principal(krb5_context context,
                 kh_db_context *kh,
                 krb5_const_principal princ,
                 unsigned int hflags,
                 krb5_db_entry *kentry);

void
kh_kdb_free_entry(krb5_context context,
                  kh_db_context *kh,
                  krb5_db_entry *entry);

krb5_error_code
kh_decrypt_key(krb5_context context,
               kh_db_context *kh,
               const krb5_key_data *key_data,
               krb5_keyblock *dbkey,
               krb5_keysalt *keysalt);

/* kdb_windc.c */

krb5_error_code
kh_db_sign_auth_data(krb5_context context,
                     unsigned int method,
                     const krb5_data *req_data,
                     krb5_data *rep_data);

krb5_error_code
kh_db_check_policy_as(krb5_context context,
                      unsigned int method,
                      const krb5_data *req_data,
                      krb5_data *rep_data);

krb5_error_code
kh_hdb_windc_init(krb5_context context,
                  const char *libdir,
                  kh_db_context *kh);

#endif /* KRB5_KDB_HDB_H */

