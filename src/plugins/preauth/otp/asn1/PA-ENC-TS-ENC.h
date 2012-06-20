/*
 * Generated by asn1c-0.9.21 (http://lionet.info/asn1c)
 * From ASN.1 module "KerberosV5Spec2"
 * 	found in "modules/KerberosV5Spec2.asn1"
 */

#ifndef	_PA_ENC_TS_ENC_H_
#define	_PA_ENC_TS_ENC_H_


#include <asn_application.h>

/* Including external dependencies */
#include "KerberosTime.h"
#include "Microseconds.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* PA-ENC-TS-ENC */
typedef struct PA_ENC_TS_ENC {
	KerberosTime_t	 patimestamp;
	Microseconds_t	*pausec	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} PA_ENC_TS_ENC_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_PA_ENC_TS_ENC;

#ifdef __cplusplus
}
#endif

#endif	/* _PA_ENC_TS_ENC_H_ */