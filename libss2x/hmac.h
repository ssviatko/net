#ifndef HMAC_H
#define HMAC_H

#ifdef __cplusplus
extern "C" {
#endif

void hmacsha224(unsigned char *key, int keylen, unsigned char *msg, int msglen, unsigned char *dig);
void hmacsha256(unsigned char *key, int keylen, unsigned char *msg, int msglen, unsigned char *dig);
void hmacsha384(unsigned char *key, int keylen, unsigned char *msg, int msglen, unsigned char *dig);
void hmacsha512(unsigned char *key, int keylen, unsigned char *msg, int msglen, unsigned char *dig);

#ifdef __cplusplus
}
#endif

#endif /* HMAC_H */

