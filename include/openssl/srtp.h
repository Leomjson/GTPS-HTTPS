#ifndef HEADER_D1_SRTP_H
# define HEADER_D1_SRTP_H

# include <openssl/ssl.hpp>

#ifdef  __cplusplus
extern "C" {
#endif

# define SRTP_AES128_CM_SHA1_80 0x0001
# define SRTP_AES128_CM_SHA1_32 0x0002
# define SRTP_AES128_F8_SHA1_80 0x0003
# define SRTP_AES128_F8_SHA1_32 0x0004
# define SRTP_NULL_SHA1_80      0x0005
# define SRTP_NULL_SHA1_32      0x0006

# define SRTP_AEAD_AES_128_GCM  0x0007
# define SRTP_AEAD_AES_256_GCM  0x0008

# ifndef OPENSSL_NO_SRTP

__owur int SSL_CTX_set_tlsext_use_srtp(SSL_CTX *ctx, const char *profiles);
__owur int SSL_set_tlsext_use_srtp(SSL *ssl, const char *profiles);

__owur STACK_OF(SRTP_PROTECTION_PROFILE) *SSL_get_srtp_profiles(SSL *ssl);
__owur SRTP_PROTECTION_PROFILE *SSL_get_selected_srtp_profile(SSL *s);

# endif

#ifdef  __cplusplus
}
#endif

#endif
