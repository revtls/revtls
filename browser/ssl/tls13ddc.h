/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * This file is PRIVATE to SSL.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef __tls13ddc_h_
#define __tls13ddc_h_

struct sslDDCStr {

    SECItem id;

    PRUint32 validTime;

    SECItem rawTBSDDC;

    SECItem domainOwner;

    SECItem middleBox;

    SECItem verificationMethod;

    SSLSignatureScheme expectedCertVerifyAlg;

    SECItem derSpki;

    CERTSubjectPublicKeyInfo *spki;

    SECKEYPublicKey *pubkey;

    SSLSignatureScheme alg;

    SECItem signature;

    SECItem rawDDC;
};

SECStatus tls13_VerifyDDC(sslSocket *ss, sslDDC *ddc);

#endif
