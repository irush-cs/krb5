/*
 * Generated by asn1c-0.9.21 (http://lionet.info/asn1c)
 * From ASN.1 module "KerberosV5Spec2"
 * 	found in "modules/KerberosV5Spec2.asn1"
 */

#ifndef	_KerberosFlags_H_
#define	_KerberosFlags_H_


#include <asn_application.h>

/* Including external dependencies */
#include <BIT_STRING.h>

#ifdef __cplusplus
extern "C" {
#endif

/* KerberosFlags */
typedef BIT_STRING_t	 KerberosFlags_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_KerberosFlags;
asn_struct_free_f KerberosFlags_free;
asn_struct_print_f KerberosFlags_print;
asn_constr_check_f KerberosFlags_constraint;
ber_type_decoder_f KerberosFlags_decode_ber;
der_type_encoder_f KerberosFlags_encode_der;
xer_type_decoder_f KerberosFlags_decode_xer;
xer_type_encoder_f KerberosFlags_encode_xer;

#ifdef __cplusplus
}
#endif

#endif	/* _KerberosFlags_H_ */