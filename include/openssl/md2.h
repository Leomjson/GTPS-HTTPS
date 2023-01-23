#ifndef HEADER_MD2_H
# define HEADER_MD2_H

# include <openssl/opensslconf.h>

# ifndef OPENSSL_NO_MD2
# include <stddef.h>
# ifdef  __cplusplus
extern "C" {
# endif

typedef unsigned char MD2_INT;

# define MD2_DIGEST_LENGTH       16
# define MD2_BLOCK               16

typedef struct MD2state_st {
    unsigned int num;
    unsigned char data[MD2_BLOCK];
    MD2_INT cksm[MD2_BLOCK];
    MD2_INT state[MD2_BLOCK];
} MD2_CTX;

const char *MD2_options(void);
int MD2_Init(MD2_CTX *c);
int MD2_Update(MD2_CTX *c, const unsigned char *data, size_t len);
int MD2_Final(unsigned char *md, MD2_CTX *c);
unsigned char *MD2(const unsigned char *d, size_t n, unsigned char *md);

# ifdef  __cplusplus
}
# endif
# endif

#endif
