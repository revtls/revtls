#include <arpa/nameser.h>

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "doh.h"

const char default_url[] = "https://dns.cloudflare.com/dns-query";

char *int_to_dns_type(uint16_t type)
{
  switch (type)
  {
	  DNS_CHECK_INT_TYPE(DNS_TYPE_A, DNS_STR_TYPE_A)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_NS, DNS_STR_TYPE_NS)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_MD, DNS_STR_TYPE_MD)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_MF, DNS_STR_TYPE_MF)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_CNAME, DNS_STR_TYPE_CNAME)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_SOA, DNS_STR_TYPE_SOA)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_MB, DNS_STR_TYPE_MB)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_MG, DNS_STR_TYPE_MG)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_MR, DNS_STR_TYPE_MR)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_NULL, DNS_STR_TYPE_NULL)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_WKS, DNS_STR_TYPE_WKS)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_PTR, DNS_STR_TYPE_PTR)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_HINFO, DNS_STR_TYPE_HINFO)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_MINFO, DNS_STR_TYPE_MINFO)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_MX, DNS_STR_TYPE_MX)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_TXT, DNS_STR_TYPE_TXT)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_RP, DNS_STR_TYPE_RP)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_AFSDB, DNS_STR_TYPE_AFSDB)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_X25, DNS_STR_TYPE_X25)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_ISDN, DNS_STR_TYPE_ISDN)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_RT, DNS_STR_TYPE_RT)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_NSAP, DNS_STR_TYPE_NSAP)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_NSAP_PTR, DNS_STR_TYPE_NSAP_PTR)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_SIG, DNS_STR_TYPE_SIG)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_KEY, DNS_STR_TYPE_KEY)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_PX, DNS_STR_TYPE_PX)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_GPOS, DNS_STR_TYPE_GPOS)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_AAAA, DNS_STR_TYPE_AAAA)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_LOC, DNS_STR_TYPE_LOC)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_NXT, DNS_STR_TYPE_NXT)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_EID, DNS_STR_TYPE_EID)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_NIMLOC, DNS_STR_TYPE_NIMLOC)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_SRV, DNS_STR_TYPE_SRV)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_ATMA, DNS_STR_TYPE_ATMA)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_NAPTR, DNS_STR_TYPE_NAPTR)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_KX, DNS_STR_TYPE_KX)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_CERT, DNS_STR_TYPE_CERT)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_A6, DNS_STR_TYPE_A6)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_DNAME, DNS_STR_TYPE_DNAME)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_SINK, DNS_STR_TYPE_SINK)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_OPT, DNS_STR_TYPE_OPT)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_APL, DNS_STR_TYPE_APL)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_DS, DNS_STR_TYPE_DS)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_SSHFP, DNS_STR_TYPE_SSHFP)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_IPSECKEY, DNS_STR_TYPE_IPSECKEY)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_RRSIG, DNS_STR_TYPE_RRSIG)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_NSEC, DNS_STR_TYPE_NSEC)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_DNSKEY, DNS_STR_TYPE_DNSKEY)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_DHCID, DNS_STR_TYPE_DHCID)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_NSEC3, DNS_STR_TYPE_NSEC3)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_NSEC3PARAM, DNS_STR_TYPE_NSEC3PARAM)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_TLSA, DNS_STR_TYPE_TLSA)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_SMIMEA, DNS_STR_TYPE_SMIMEA)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_HIP, DNS_STR_TYPE_HIP)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_NINFO, DNS_STR_TYPE_NINFO)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_RKEY, DNS_STR_TYPE_RKEY)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_TALINK, DNS_STR_TYPE_TALINK)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_CDS, DNS_STR_TYPE_CDS)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_CDNSKEY, DNS_STR_TYPE_CDNSKEY)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_OPENPGPKEY, DNS_STR_TYPE_OPENPGPKEY)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_CSYNC, DNS_STR_TYPE_CSYNC)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_ZONEMD, DNS_STR_TYPE_ZONEMD)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_SVCB, DNS_STR_TYPE_SVCB)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_HTTPS, DNS_STR_TYPE_HTTPS)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_SPF, DNS_STR_TYPE_SPF)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_UINFO, DNS_STR_TYPE_UINFO)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_UID, DNS_STR_TYPE_UID)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_GID, DNS_STR_TYPE_GID)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_UNSPEC, DNS_STR_TYPE_UNSPEC)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_NID, DNS_STR_TYPE_NID)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_L32, DNS_STR_TYPE_L32)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_L64, DNS_STR_TYPE_L64)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_LP, DNS_STR_TYPE_LP)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_EUI48, DNS_STR_TYPE_EUI48)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_EUI64, DNS_STR_TYPE_EUI64)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_TKEY, DNS_STR_TYPE_TKEY)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_TSIG, DNS_STR_TYPE_TSIG)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_IXFR, DNS_STR_TYPE_IXFR)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_AXFR, DNS_STR_TYPE_AXFR)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_MAILB, DNS_STR_TYPE_MAILB)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_MAILA, DNS_STR_TYPE_MAILA)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_URI, DNS_STR_TYPE_URI)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_CAA, DNS_STR_TYPE_CAA)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_AVC, DNS_STR_TYPE_AVC)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_DOA, DNS_STR_TYPE_DOA)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_AMTREPLAY, DNS_STR_TYPE_AMTREPLAY)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_TA, DNS_STR_TYPE_TA)
	  DNS_CHECK_INT_TYPE(DNS_TYPE_DLV, DNS_STR_TYPE_DLV)

	default:
	  return "ERROR";
	  break;
  }
}
static DOHcode skipqname(unsigned char *doh, size_t dohlen,
	unsigned int *indexp)
{
  unsigned char length;
  do {
	if(dohlen < (*indexp + 1))
	  return DOH_DNS_OUT_OF_RANGE;
	length = doh[*indexp];
	if((length & 0xc0) == 0xc0) {
	  /* name pointer, advance over it and be done */
	  if(dohlen < (*indexp + 2))
		return DOH_DNS_OUT_OF_RANGE;
	  *indexp += 2;
	  break;
	}
	if(length & 0xc0)
	  return DOH_DNS_BAD_LABEL;
	if(dohlen < (*indexp + 1 + length))
	  return DOH_DNS_OUT_OF_RANGE;
	*indexp += 1 + length;
  } while (length);
  return DOH_OK;
}

static unsigned short get16bit(unsigned char *doh, int index)
{
  return ((doh[index] << 8) | doh[index + 1]);
}

static unsigned int get32bit(unsigned char *doh, int index)
{
  return (doh[index] << 24) | (doh[index+1] << 16) |
	(doh[index+2] << 8) | doh[index+3];
}

static DOHcode rdata(unsigned char *doh,
	size_t dohlen,
	unsigned short rdlength,
	unsigned short type)
{
  DOHcode rc;
  bool cloud_flare = false;

  if (type != DNS_TYPE_NSEC)
	return DOH_DNS_BAD_RCODE;

  if(rdlength <= 1)
	return DOH_DNS_RDATA_LEN;

  int index = dohlen - rdlength;
  if (doh[index] == 0x01 && doh[index+1] == 0)
	cloud_flare = true;

  while (doh[index] != 0) {
	index += doh[index];
	index++;
  }

  index += 2;
  int nsec_length = doh[index];
  index++;

  if (cloud_flare) {
	if (!(doh[index] & 1 << 6))
	  return DOH_DNS_BAD_RCODE;
  }

  for (int j = 0; j < nsec_length; j++) {
	for (int k = 7; k >= 0; k--) {
	  if (doh[index + j] & (1 << k)) {
		printf("%s\n", int_to_dns_type((j*8)+(7-k)));
	  }
	}
  }

  return DOH_OK;
}


static void doh_init(struct dnsentry *d)
{
  memset(d, 0, sizeof(struct dnsentry));
  d->ttl = ~0u; /* default to max */
}

static void doh_cleanup(struct dnsentry *d)
{
  int i = 0;
  for(i=0; i< d->numcname; i++) {
	free(d->cname[i].alloc);
  }
}

static size_t doh_encode(const char *host,
	int dnstype,
	unsigned char *dnsp, /* buffer */
	size_t len) /* buffer size */
{
  size_t hostlen = strlen(host);
  unsigned char *orig = dnsp;
  const char *hostp = host;

  if(len < (12 + hostlen + 6))
	return 0;

  *dnsp++ = 0; /* 16 bit id */
  *dnsp++ = 0;
  *dnsp++ = 0x01; /* |QR|   Opcode  |AA|TC|RD| Set the RD bit */
  *dnsp++ = '\0'; /* |RA|   Z    |   RCODE   |                */
  *dnsp++ = '\0';
  *dnsp++ = 1;    /* QDCOUNT (number of entries in the question section) */
  *dnsp++ = '\0';
  *dnsp++ = '\0'; /* ANCOUNT */
  *dnsp++ = '\0';
  *dnsp++ = '\0'; /* NSCOUNT */
  *dnsp++ = '\0';
  *dnsp++ = '\0'; /* ARCOUNT */

  /* store a QNAME */
  do {
	char *dot = strchr(hostp, '.');
	size_t labellen;
	bool found = false;
	if(dot) {
	  found = true;
	  labellen = dot - hostp;
	}
	else
	  labellen = strlen(hostp);
	if(labellen > 63)
	  /* too long label, error out */
	  return 0;
	*dnsp++ = (unsigned char)labellen;
	memcpy(dnsp, hostp, labellen);
	dnsp += labellen;
	hostp += labellen + 1;
	if(!found) {
	  *dnsp++ = 0; /* terminating zero */
	  break;
	}
  } while(1);

  *dnsp++ = '\0'; /* upper 8 bit TYPE */
  *dnsp++ = (unsigned char)dnstype;
  *dnsp++ = '\0'; /* upper 8 bit CLASS */
  *dnsp++ = DNS_CLASS_IN; /* IN - "the Internet" */

  return dnsp - orig;
}

static DOHcode doh_decode(unsigned char *doh,
	size_t dohlen,
	int dnstype,
	struct dnsentry *d)
{
  unsigned char qr;
  unsigned char rcode;
  unsigned short qdcount;
  unsigned short ancount;
  unsigned short type=0;
  unsigned short class;
  unsigned short rdlength;
  unsigned short nscount;
  unsigned short arcount;
  unsigned int index = 12;
  DOHcode rc;

  qr = doh[2] & 0x80;
  if(dohlen < 12 || doh[0] || doh[1] || !qr)
	return DOH_DNS_MALFORMAT; /* too small or bad ID or not a response */
  rcode = doh[3] & 0x0f;
  if(rcode)
	return DOH_DNS_BAD_RCODE; /* bad rcode */

  qdcount = get16bit(doh, 4);
  while (qdcount) {
	rc = skipqname(doh, dohlen, &index);
	if(rc)
	  return rc; /* bad qname */
	if(dohlen < (index + 4))
	  return DOH_DNS_OUT_OF_RANGE;
	index += 4; /* skip question's type and class */
	qdcount--;
  }

  ancount = get16bit(doh, 6);
  while (ancount) {
	unsigned int ttl;

	rc = skipqname(doh, dohlen, &index);
	if(rc)
	  return rc; /* bad qname */

	if(dohlen < (index + 2))
	  return DOH_DNS_OUT_OF_RANGE;

	type = get16bit(doh, index);
	if((type != DNS_TYPE_CNAME) && (type != dnstype))
	  /* Not the same type as was asked for nor CNAME */
	  return DOH_DNS_UNEXPECTED_TYPE;
	index += 2;

	if(dohlen < (index + 2))
	  return DOH_DNS_OUT_OF_RANGE;
	class = get16bit(doh, index);
	if(DNS_CLASS_IN != class)
	  return DOH_DNS_UNEXPECTED_CLASS; /* unsupported */
	index += 2;

	if(dohlen < (index + 4))
	  return DOH_DNS_OUT_OF_RANGE;

	ttl = get32bit(doh, index);
	if(ttl < d->ttl)
	  d->ttl = ttl;
	index += 4;

	if(dohlen < (index + 2))
	  return DOH_DNS_OUT_OF_RANGE;

	rdlength = get16bit(doh, index);
	index += 2;
	if(dohlen < (index + rdlength))
	  return DOH_DNS_OUT_OF_RANGE;

	rc = rdata(doh, dohlen, rdlength, type);
	if(rc)
	  return rc; /* bad rdata */
	index += rdlength;
	ancount--;
  }

  nscount = get16bit(doh, 8);
  while (nscount) {
	rc = skipqname(doh, dohlen, &index);
	if(rc)
	  return rc; /* bad qname */

	if(dohlen < (index + 8))
	  return DOH_DNS_OUT_OF_RANGE;

	index += 2; /* type */
	index += 2; /* class */
	index += 4; /* ttl */

	if(dohlen < (index + 2))
	  return DOH_DNS_OUT_OF_RANGE;

	rdlength = get16bit(doh, index);
	index += 2;
	if(dohlen < (index + rdlength))
	  return DOH_DNS_OUT_OF_RANGE;
	index += rdlength;
	nscount--;
  }

  arcount = get16bit(doh, 10);
  while (arcount) {
	rc = skipqname(doh, dohlen, &index);
	if(rc)
	  return rc; /* bad qname */

	if(dohlen < (index + 8))
	  return DOH_DNS_OUT_OF_RANGE;

	index += 2; /* type */
	index += 2; /* class */
	index += 4; /* ttl */

	rdlength = get16bit(doh, index);
	index += 2;
	if(dohlen < (index + rdlength))
	  return DOH_DNS_OUT_OF_RANGE;
	index += rdlength;
	arcount--;
  }

  if(index != dohlen)
	return DOH_DNS_MALFORMAT; /* something is wrong */

  if((type != DNS_TYPE_NS) && !d->numcname && !d->numv6 && !d->numv4 && !d->numtxt)
	/* nothing stored! */
	return DOH_NO_CONTENT;

  return DOH_OK; /* ok */
}

  static size_t
write_cb(void *contents, size_t size, size_t nmemb, void *userp)
{
  size_t realsize = size * nmemb;
  struct response *mem = (struct response *)userp;

  mem->memory = realloc(mem->memory, mem->size + realsize);
  if(mem->memory == NULL) {
	/* out of memory! */
	printf("not enough memory (realloc returned NULL)\n");
	return 0;
  }

  memcpy(&(mem->memory[mem->size]), contents, realsize);
  mem->size += realsize;

  return realsize;
}

static int initprobe(int dnstype, char *host, const char *url, CURLM *multi,
	struct curl_slist *headers,
	bool insecure_mode, enum iptrans transport,
	struct curl_slist *resolve)
{
  CURL *curl;
  struct dnsprobe *p = calloc((size_t)1, sizeof *p);
  if(p == NULL) {
	fprintf(stderr, "Failed to allocate memory\n");
	return 1;
  }
  p->dohlen = doh_encode(host, dnstype, p->dohbuffer, sizeof(p->dohbuffer));
  if(!p->dohlen) {
	fprintf(stderr, "Failed to encode DOH packet\n");
	return 2;
  }

  p->dnstype = dnstype;
  p->serverdoh.memory = malloc(1);  /* will be grown as needed by realloc above */
  p->serverdoh.size = 0;    /* no data at this point */
  p->config.trace_ascii = 0; /* enable ascii tracing */

  curl = curl_easy_init();
  if(curl) {
	if(transport == v4)
	  curl_easy_setopt(curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
	else if(transport == v6)
	  curl_easy_setopt(curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V6);
	if(resolve != NULL)
	  curl_easy_setopt(curl, CURLOPT_RESOLVE, resolve);
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&p->serverdoh);
	curl_easy_setopt(curl, CURLOPT_USERAGENT, "curl-doh/1.0");
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, p->dohbuffer);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, p->dohlen);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2);
	curl_easy_setopt(curl, CURLOPT_PRIVATE, p);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, insecure_mode?0L:1L);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, insecure_mode?0L:1L);

	p->curl = curl;

	/* add the individual transfers */
	curl_multi_add_handle(multi, curl);
  }
  else {
	fprintf(stderr, "curl_easy_init() failed\n");
	return 3;
  }

  return 0;
}


SECStatus nsec_record_request(const char *host)
{
  int rc;
  CURLMsg *msg;
  struct curl_slist *headers = NULL;
  struct curl_slist *resolve = NULL;
  enum iptrans transport = v46;
  bool insecure_mode = false;
  int test_mode = 0;
  int still_running;
  int repeats = 0;
  int queued;
  int successful = 0;

  CURLM *multi;
  struct dnsentry d;

  curl_global_init(CURL_GLOBAL_ALL);

  /* use the older content-type */
  headers = curl_slist_append(headers, "Content-Type: application/dns-message");
  headers = curl_slist_append(headers, "Accept: application/dns-message");

  /* init a multi stack */
  multi = curl_multi_init();

  doh_init(&d);

  rc = initprobe(DNS_TYPE_NSEC, host, default_url, multi,
	  headers, insecure_mode,
	  transport, resolve);
  if(rc != 0) {
	fprintf(stderr, "initprobe() failed (DNS_TYPE_NSEC)\n");
	return SECFailure;
  }

  /* we start some action by calling perform right away */
  curl_multi_perform(multi, &still_running);

  do {
	CURLMcode mc; /* curl_multi_wait() return code */
	int numfds;

	/* wait for activity, timeout or "nothing" */
	mc = curl_multi_wait(multi, NULL, 0, 1000, &numfds);

	if(mc != CURLM_OK) {
	  fprintf(stderr, "curl_multi_wait() failed, code %d.\n", mc);
	  break;
	}

	/* 'numfds' being zero means either a timeout or no file descriptors to
	   wait for. Try timeout on first occurrence, then assume no file
	   descriptors and no file descriptors to wait for means wait for 100
	   milliseconds. */

	if(!numfds) {
	  repeats++; /* count number of repeated zero numfds */
	  if(repeats > 1) {
		WAITMS(10); /* sleep 10 milliseconds */
	  }
	}
	else
	  repeats = 0;

	curl_multi_perform(multi, &still_running);

	while((msg = curl_multi_info_read(multi, &queued))) {
	  if(msg->msg == CURLMSG_DONE) {
		struct dnsprobe *probe;
		CURL *e = msg->easy_handle;
		curl_easy_getinfo(msg->easy_handle, CURLINFO_PRIVATE, &probe);

		/* Check for errors */
		if(msg->data.result != CURLE_OK) {
		  fprintf(stderr, "probe for NSEC failed: %s\n",
			  curl_easy_strerror(msg->data.result));
		  return SECFailure;
		}
		else {
		  long response_code;
		  curl_easy_getinfo(e, CURLINFO_RESPONSE_CODE, &response_code);
		  if((response_code / 100 ) == 2) {
			rc = doh_decode(probe->serverdoh.memory,
				probe->serverdoh.size,
				probe->dnstype, &d);
			if(rc) {
			  if(rc == DOH_DNS_BAD_RCODE) {
				//fprintf(stderr, "Bad rcode, %s (NSEC)\n",
					//host);
				return SECSuccess;
			  } else if(rc != DOH_NO_CONTENT) {
				fprintf(stderr, "problem %d decoding %" FMT_SIZE_T
					" bytes response to probe for NSEC\n",
					rc, probe->serverdoh.size);
				return SECFailure;
			  }
			}
			else
			  successful++;
		  }
		  else {
			fprintf(stderr, "Probe for NSEC got response: %03ld\n",
				response_code);
		  }
		  free(probe->serverdoh.memory);
		}
		curl_multi_remove_handle(multi, e);
		curl_easy_cleanup(e);
		free(probe);
	  }
	}
  } while(still_running && (successful == 0 || test_mode == 0));

  doh_cleanup(&d);
  if(headers != NULL)
	curl_slist_free_all(headers);
  if(resolve != NULL)
	curl_slist_free_all(resolve);
  curl_multi_cleanup(multi);

  /* we're done with libcurl, so clean it up */
  curl_global_cleanup();

  return SECFailure;
}
