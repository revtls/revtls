#include "nss.h"
#include "pk11func.h"
#include "secder.h"
#include "sechash.h"
#include "ssl.h"
#include "sslproto.h"
#include "sslimpl.h"
#include "ssl3exthandle.h"
#include "tls13exthandle.h"
#include "tls13hkdf.h"
#include "tls13subcerts.h"
#include "tls13ddc.h"
#include "utils.h"
#include "doh.h"

static char ddc_txt_record[2048];

PRBool
tls13_IsVerifyingWithDDC(const sslSocket *ss)
{
    /* We currently do not support client-delegated credentials. */
    if (ss->xtnData.ddcKeyLocation.data==NULL) {
        return PR_FALSE;
    }

    return PR_TRUE;
}

static SECStatus
tls13_HashDDCSignatureMessage(SSL3Hashes *hash,
                             const CERTCertificate *cert,
                             const sslDDC *ddc)
{
    SECStatus rv;
    PK11Context *ctx = NULL;
    unsigned int hashLen;

    /* Set up hash context. */
    ctx = PK11_CreateDigestContext(ssl3_HashTypeToOID(hash->hashAlg));
    if (!ctx) {
        printf("PK11_CreateDigestContext failed\n");
        PORT_SetError(SEC_ERROR_NO_MEMORY);
        return SECFailure;
    }

    int outLen;
    //Todo: Method to allocate memory size for decodedRawDDC
    unsigned char *decodedRawDDC = (unsigned char *)PORT_Alloc(100000);
    outLen = base64_decode(ddc->rawTBSDDC.data, decodedRawDDC, strlen(ddc->rawTBSDDC.data));
    decodedRawDDC[outLen]='\0';

    /* Hash the message signed by the peer. */
    rv = SECSuccess;
    rv |= PK11_DigestBegin(ctx);
    rv |= PK11_DigestOp(ctx, decodedRawDDC, strlen(decodedRawDDC));
    rv |= PK11_DigestFinal(ctx, hash->u.raw, &hashLen, sizeof hash->u.raw);
    if (rv != SECSuccess) {
        PORT_SetError(SSL_ERROR_SHA_DIGEST_FAILURE);
        printf("Digest failed\n");
        return SECFailure;
    }

    hash->len = hashLen;
    if (ctx) {
        PK11_DestroyContext(ctx, PR_TRUE);
    }

    //printf("ddc->rawTBSDDC.data bytes: %d %d %d\n", decodedRawDDC[0], decodedRawDDC[1], decodedRawDDC[2]);

    PORT_Free(decodedRawDDC);

    return SECSuccess;
}

static SECStatus
tls13_VerifyDDCSignature(sslSocket *ss, sslDDC *ddc)
{
    SECStatus rv = SECSuccess;
    SSL3Hashes hash;
    CERTCertificate *cert = ss->sec.peerCert;
    SECKEYPublicKey *pubKey = NULL;

    hash.hashAlg = ssl_hash_sha256;

    rv = tls13_HashDDCSignatureMessage(&hash, cert, ddc);
    if (rv != SECSuccess) {
        FATAL_ERROR(ss, PORT_GetError(), internal_error);
        return SECFailure;
    }
    pubKey = SECKEY_ExtractPublicKey(&cert->subjectPublicKeyInfo);
    if (pubKey == NULL) {
        FATAL_ERROR(ss, SSL_ERROR_EXTRACT_PUBLIC_KEY_FAILURE, internal_error);
        return SECFailure;
    }

    //printf("signature: %s\n", ddc->signature.data);
    int outLen;
    unsigned char *decodedSignature = (unsigned char *)PORT_Alloc(300);
    outLen = base64_decode(ddc->signature.data, decodedSignature, strlen(ddc->signature.data));
    decodedSignature[outLen]='\0';
    //printf("(tls13_VerifyDDCSignature) signature decoded %d %d %d\n", decodedSignature[0], decodedSignature[1], decodedSignature[2]);
    //printf("(tls13_VerifyDDCSignature) hash->u.raw[0], hash->u.raw[1]: %d  %d outlen %d\n", hash.u.raw[0], hash.u.raw[1], outLen);

    ddc->signature.data = decodedSignature;
    ddc->signature.data[outLen] = '\0';
    ddc->signature.len = outLen;

    //printf("(tls13_VerifyDDCSignature) ddc->signature.data: %d  %d\n", ddc->signature.data[0], ddc->signature.data[outLen-1]);

    rv = ssl_VerifySignedHashesWithPubKey(ss, pubKey, ssl_sig_ecdsa_secp256r1_sha256,
                                          &hash, &ddc->signature);
    if (rv != SECSuccess) {
        printf("DDC verification failed\n");
        FATAL_ERROR(ss, SSL_ERROR_DDC_BAD_SIGNATURE, illegal_parameter);
        return SECFailure;
    }

    PORT_Free(decodedSignature);
    printf("Success a DDC verification\n");
    return SECSuccess;
}

static uint8_t hex_to_byte(char * Text, int Length)
{
  uint8_t byte = 0;
  for (int i = 0; i < Length; ++i)
  {
	char character = Text[i];
	byte <<= 4;
	if (character >= '0' && character <= '9')
	  byte += character - '0';
	else if (character <= 'F' && character >= 'A')
	  byte += character - 'A' + 10;
	else if (character <= 'f' && character >= 'a')
	  byte += character - 'a' + 10;
  }
  return byte;
}

static SECStatus
tls13_HandleDDCSerial(SECItem *serial, unsigned char *ddcBytes){
  unsigned char *searchSerial = strstr(ddcBytes, "\"SerialNumber\":")+15;
  serial->len = strcspn(searchSerial, ",");
  serial->data = (unsigned char *)PORT_Alloc(serial->len);
  strncpy(serial->data, searchSerial, serial->len);
  serial->data[serial->len]='\0';
  serial->type = siBuffer;

  return SECSuccess;
}

static SECStatus
tls13_HandleDDCVersion(SECItem *version, unsigned char *ddcBytes){
  unsigned char *searchVersion = strstr(ddcBytes, "\"Version\":")+10;
  version->len = strcspn(searchVersion, ",");
  version->data = (unsigned char *)PORT_Alloc(version->len);
  strncpy(version->data, searchVersion, version->len);
  version->data[version->len]='\0';
  version->type = siBuffer;

  return SECSuccess;
}

static SECStatus
tls13_HandleNotBefore(SECItem *notbefore, unsigned char *ddcBytes){
  unsigned char *searchNotBefore = strstr(ddcBytes, "\"NotBefore\":")+13;
  notbefore->len = strcspn(searchNotBefore, "\"");
  notbefore->data = (unsigned char *)PORT_Alloc(notbefore->len);
  strncpy(notbefore->data, searchNotBefore, notbefore->len);
  notbefore->data[notbefore->len] = '\0';
  notbefore->type = siBuffer;

  return SECSuccess;
}

static SECStatus
tls13_HandleNotAfter(SECItem *notafter, unsigned char *ddcBytes){
  unsigned char *searchNotAfter = strstr(ddcBytes, "\"NotAfter\":")+12;
  notafter->len = strcspn(searchNotAfter, "\"");
  notafter->data = (unsigned char *)PORT_Alloc(notafter->len);
  strncpy(notafter->data, searchNotAfter, notafter->len);
  notafter->data[notafter->len] = '\0';
  notafter->type = siBuffer;

  return SECSuccess;
}

static SECStatus
tls13_HandleDDCSignature(SECItem *signature, unsigned char *ddcBytes){
  signature->data = strstr(ddcBytes, "\"Signature\":")+13;
  signature->data[96] = '\0';
  signature->len = strlen(signature->data);
  signature->type = siBuffer;

  return SECSuccess;
}

static SECStatus
tls13_HashDDCProofMessage(SSL3Hashes *hash,
	const CERTCertificate *cert,
	const sslDDC *ddc,
	SECItem parsedSerial, uint16_t version,
	SECItem parsedNotBefore, SECItem parsedNotAfter)
{
  SECStatus rv;
  PK11Context *ctx = NULL;
  unsigned int hashLen;

  /* Set up hash context. */
  ctx = PK11_CreateDigestContext(ssl3_HashTypeToOID(hash->hashAlg));
  if (!ctx) {
	//printf("PK11_CreateDigestContext failed\n");
	PORT_SetError(SEC_ERROR_NO_MEMORY);
	return SECFailure;
  }

  unsigned char *decodedDDCProof = (unsigned char *)PORT_Alloc(1024);
  int byte_len = 0;
  int serial_len = 18;
  byte_len += serial_len;
  BigInt_t *serial = PORT_Alloc(BigIntWordSize*serial_len);
  BigInt_from_string(serial_len, serial, parsedSerial.data);
  unsigned char serial_hex_str[128];
  BigInt_to_hex_string(serial_len, serial, serial_hex_str);
  for (int i = 0; i < serial_len; i++) {
	char num_str[3];
	strncpy(&num_str, &serial_hex_str[i*2], 2);
	decodedDDCProof[i] = hex_to_byte(num_str, 2);
  }
  memcpy(decodedDDCProof + byte_len, &version, sizeof(version));
  byte_len += sizeof(version);

  memcpy(decodedDDCProof + byte_len, parsedNotBefore.data, parsedNotBefore.len);
  byte_len += parsedNotBefore.len;

  memcpy(decodedDDCProof + byte_len, parsedNotAfter.data, parsedNotAfter.len);
  byte_len += parsedNotAfter.len;

  /* Hash the message signed by the peer. */
  rv = SECSuccess;
  rv |= PK11_DigestBegin(ctx);
  rv |= PK11_DigestOp(ctx, decodedDDCProof, byte_len);
  rv |= PK11_DigestFinal(ctx, hash->u.raw, &hashLen, sizeof hash->u.raw);
  if (rv != SECSuccess) {
	PORT_SetError(SSL_ERROR_SHA_DIGEST_FAILURE);
	//printf("Digest failed\n");
	return SECFailure;
  }

  hash->len = hashLen;
  if (ctx) {
	PK11_DestroyContext(ctx, PR_TRUE);
  }

  PORT_Free(serial);
  PORT_Free(decodedDDCProof);

  return SECSuccess;
}

static SECStatus
tls13_CheckDDCProofExpiration(char *before, char *after)
{
  struct tm before_tmdate = {0};
  before_tmdate.tm_year = atoi(&before[0]) - 1900;
  before_tmdate.tm_mon = atoi(&before[5]) - 1;
  before_tmdate.tm_mday = atoi(&before[8]);
  before_tmdate.tm_hour = atoi(&before[11]);
  before_tmdate.tm_min = atoi(&before[14]);
  before_tmdate.tm_sec = atoi(&before[17]);
  time_t before_time = mktime( &before_tmdate );

  struct tm after_tmdate = {0};
  after_tmdate.tm_year = atoi(&after[0]) - 1900;
  after_tmdate.tm_mon = atoi(&after[5]) - 1;
  after_tmdate.tm_mday = atoi(&after[8]);
  after_tmdate.tm_hour = atoi(&after[11]);
  after_tmdate.tm_min = atoi(&after[14]);
  after_tmdate.tm_sec = atoi(&after[17]);
  time_t after_time = mktime( &after_tmdate );

  time_t now;
  time(&now);

  if (now < before_time || now > after_time)
	return SECFailure;

  return SECSuccess;
}

static SECStatus
tls13_ValidateDDC(sslSocket *ss, sslDDC *ddc)
{
  SECStatus rv = SECSuccess;

  char url[100] = {0,};

  strcpy(url, ddc->id.data);
  strcat(url, ".sspki.com");

  rv = nsec_record_request(url);
  if (rv != SECSuccess)
	return SECFailure;

  return SECSuccess;
}

static SECStatus
tls13_CheckCertDDCUsage(sslSocket *ss){
    int i;
    CERTCertExtension *ext;
    const CERTCertificate *cert = ss->sec.peerCert;

    if (!cert->keyUsagePresent ||
        !(cert->keyUsage & KU_DIGITAL_SIGNATURE)) {
        FATAL_ERROR(ss, SSL_ERROR_DDC_INVALID_KEY_USAGE, illegal_parameter);
        return SECFailure;
    }

    return SECSuccess;

}

SECStatus
tls13_VerifyDDC(sslSocket *ss, sslDDC *ddc)
{
    SECStatus rv;

    rv = SECSuccess;
    rv |= tls13_VerifyDDCSignature(ss, ddc);
    rv |= tls13_ValidateDDC(ss, ddc);
    rv |= tls13_CheckCertDDCUsage(ss);
    //rv |= tls13_CheckCredentialExpiration(ss, ddc);
    return rv;
}

SECStatus
DDC_TxtRecordSet(char *txt_record)
{
	memset(ddc_txt_record, 0, 2048);
	strcpy(ddc_txt_record, txt_record);

	return SECSuccess;
}
