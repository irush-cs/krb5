/*
 * Generated by asn1c-0.9.21 (http://lionet.info/asn1c)
 * From ASN.1 module "OTPKerberos"
 * 	found in "modules/otp-preauth-21.asn1"
 */

#ifndef	_PinFlags_H_
#define	_PinFlags_H_


#include <asn_application.h>

/* Including external dependencies */
#include "KerberosFlags.h"

#ifdef __cplusplus
extern "C" {
#endif

/* PinFlags */
typedef KerberosFlags_t	 PinFlags_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_PinFlags;
asn_struct_free_f PinFlags_free;
asn_struct_print_f PinFlags_print;
asn_constr_check_f PinFlags_constraint;
ber_type_decoder_f PinFlags_decode_ber;
der_type_encoder_f PinFlags_encode_der;
xer_type_decoder_f PinFlags_decode_xer;
xer_type_encoder_f PinFlags_encode_xer;

#ifdef __cplusplus
}
#endif

#endif	/* _PinFlags_H_ */