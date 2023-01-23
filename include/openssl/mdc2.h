#ifndef HEADER_MDC2_H
# define HEADER_MDC2_H

# include <openssl/opensslconf.h>

#ifndef OPENSSL_NO_MDC2
# include <stdlib.h>
# include <openssl/des.h>
# ifdef  __cplusplus
extern "C" {
# endif

# define MDC2_BLOCK              8
# define MDC2_DIGEST_LENGTH      16

typedef struct mdc2_ctx_st {
    unsigned int num;
    unsigned char data[MDC2_BLOCK];
    DES_cblock h, hh;
    int pad_type;                      
} MDC2_CTX;

int MDC2_Init(MDC2_CTX *c);
int MDC2_Update(MDC2_CTX *c, const unsigned char *data, size_t len);
int MDC2_Final(unsigned char *md, MDC2_CTX *c);
unsigned char *MDC2(const unsigned char *d, size_t n, unsigned char *md);

# ifdef  __cplusplus
}
# endif
# endif

#endif
