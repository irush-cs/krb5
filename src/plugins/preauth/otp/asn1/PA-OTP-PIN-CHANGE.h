/*
 * Generated by asn1c-0.9.21 (http://lionet.info/asn1c)
 * From ASN.1 module "OTPKerberos"
 * 	found in "modules/otp-preauth-21.asn1"
 */

#ifndef	_PA_OTP_PIN_CHANGE_H_
#define	_PA_OTP_PIN_CHANGE_H_


#include <asn_application.h>

/* Including external dependencies */
#include "PinFlags.h"
#include <UTF8String.h>
#include <INTEGER.h>
#include "OTPFormat.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct LastReq;

/* PA-OTP-PIN-CHANGE */
typedef struct PA_OTP_PIN_CHANGE {
	PinFlags_t	 flags;
	UTF8String_t	*pin	/* OPTIONAL */;
	INTEGER_t	*minLength	/* OPTIONAL */;
	INTEGER_t	*maxLength	/* OPTIONAL */;
	struct LastReq	*last_req	/* OPTIONAL */;
	OTPFormat_t	*format	/* OPTIONAL */;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} PA_OTP_PIN_CHANGE_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_PA_OTP_PIN_CHANGE;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "LastReq.h"

#endif	/* _PA_OTP_PIN_CHANGE_H_ */