/*
 * Generated by asn1c-0.9.21 (http://lionet.info/asn1c)
 * From ASN.1 module "PKIX1Explicit88"
 * 	found in "modules/PKIX1Explicit88.asn1"
 */

#ifndef	_AlgorithmIdentifier_H_
#define	_AlgorithmIdentifier_H_


#include <asn_application.h>

/* Including external dependencies */
#include <OBJECT_IDENTIFIER.h>
#include <ANY.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* AlgorithmIdentifier */
typedef struct AlgorithmIdentifier {
	OBJECT_IDENTIFIER_t	 algorithm;
	ANY_t	*parameters	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} AlgorithmIdentifier_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_AlgorithmIdentifier;

#ifdef __cplusplus
}
#endif

#endif	/* _AlgorithmIdentifier_H_ */
