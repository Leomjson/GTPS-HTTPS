#ifndef HEADER_EC_H
# define HEADER_EC_H

# include <openssl/opensslconf.h>

# ifndef OPENSSL_NO_EC
# include <openssl/asn1.hpp>
# include <openssl/symhacks.h>
# if OPENSSL_API_COMPAT < 0x10100000L
#  include <openssl/bn.h>
# endif
# include <openssl/ecerr.h>
# ifdef  __cplusplus
extern "C" {
# endif

# ifndef OPENSSL_ECC_MAX_FIELD_BITS
#  define OPENSSL_ECC_MAX_FIELD_BITS 661
# endif

	typedef enum {
		POINT_CONVERSION_COMPRESSED = 2,
		POINT_CONVERSION_UNCOMPRESSED = 4,
		POINT_CONVERSION_HYBRID = 6
	} point_conversion_form_t;

	typedef struct ec_method_st EC_METHOD;
	typedef struct ec_group_st EC_GROUP;
	typedef struct ec_point_st EC_POINT;
	typedef struct ecpk_parameters_st ECPKPARAMETERS;
	typedef struct ec_parameters_st ECPARAMETERS;

	const EC_METHOD* EC_GFp_simple_method(void);

	const EC_METHOD* EC_GFp_mont_method(void);

	const EC_METHOD* EC_GFp_nist_method(void);

# ifndef OPENSSL_NO_EC_NISTP_64_GCC_128
	const EC_METHOD* EC_GFp_nistp224_method(void);

	const EC_METHOD* EC_GFp_nistp256_method(void);

	const EC_METHOD* EC_GFp_nistp521_method(void);
# endif

# ifndef OPENSSL_NO_EC2M
	const EC_METHOD* EC_GF2m_simple_method(void);

# endif

	EC_GROUP* EC_GROUP_new(const EC_METHOD* meth);

	void EC_GROUP_free(EC_GROUP* group);

	void EC_GROUP_clear_free(EC_GROUP* group);

	int EC_GROUP_copy(EC_GROUP* dst, const EC_GROUP* src);

	EC_GROUP* EC_GROUP_dup(const EC_GROUP* src);

	const EC_METHOD* EC_GROUP_method_of(const EC_GROUP* group);

	int EC_METHOD_get_field_type(const EC_METHOD* meth);

	int EC_GROUP_set_generator(EC_GROUP* group, const EC_POINT* generator,
		const BIGNUM* order, const BIGNUM* cofactor);

	const EC_POINT* EC_GROUP_get0_generator(const EC_GROUP* group);

	BN_MONT_CTX* EC_GROUP_get_mont_data(const EC_GROUP* group);

	int EC_GROUP_get_order(const EC_GROUP* group, BIGNUM* order, BN_CTX* ctx);

	const BIGNUM* EC_GROUP_get0_order(const EC_GROUP* group);

	int EC_GROUP_order_bits(const EC_GROUP* group);

	int EC_GROUP_get_cofactor(const EC_GROUP* group, BIGNUM* cofactor,
		BN_CTX* ctx);

	const BIGNUM* EC_GROUP_get0_cofactor(const EC_GROUP* group);

	void EC_GROUP_set_curve_name(EC_GROUP* group, int nid);

	int EC_GROUP_get_curve_name(const EC_GROUP* group);

	void EC_GROUP_set_asn1_flag(EC_GROUP* group, int flag);
	int EC_GROUP_get_asn1_flag(const EC_GROUP* group);

	void EC_GROUP_set_point_conversion_form(EC_GROUP* group,
		point_conversion_form_t form);
	point_conversion_form_t EC_GROUP_get_point_conversion_form(const EC_GROUP*);

	unsigned char* EC_GROUP_get0_seed(const EC_GROUP* x);
	size_t EC_GROUP_get_seed_len(const EC_GROUP*);
	size_t EC_GROUP_set_seed(EC_GROUP*, const unsigned char*, size_t len);

	int EC_GROUP_set_curve(EC_GROUP* group, const BIGNUM* p, const BIGNUM* a,
		const BIGNUM* b, BN_CTX* ctx);

	int EC_GROUP_get_curve(const EC_GROUP* group, BIGNUM* p, BIGNUM* a, BIGNUM* b,
		BN_CTX* ctx);

	DEPRECATEDIN_1_2_0(int EC_GROUP_set_curve_GFp(EC_GROUP* group, const BIGNUM* p,
		const BIGNUM* a, const BIGNUM* b,
		BN_CTX* ctx))

		DEPRECATEDIN_1_2_0(int EC_GROUP_get_curve_GFp(const EC_GROUP* group, BIGNUM* p,
			BIGNUM* a, BIGNUM* b,
			BN_CTX* ctx))

# ifndef OPENSSL_NO_EC2M
		DEPRECATEDIN_1_2_0(int EC_GROUP_set_curve_GF2m(EC_GROUP* group, const BIGNUM* p,
			const BIGNUM* a, const BIGNUM* b,
			BN_CTX* ctx))

		DEPRECATEDIN_1_2_0(int EC_GROUP_get_curve_GF2m(const EC_GROUP* group, BIGNUM* p,
			BIGNUM* a, BIGNUM* b,
			BN_CTX* ctx))
# endif
		int EC_GROUP_get_degree(const EC_GROUP* group);

	int EC_GROUP_check(const EC_GROUP* group, BN_CTX* ctx);

	int EC_GROUP_check_discriminant(const EC_GROUP* group, BN_CTX* ctx);

	int EC_GROUP_cmp(const EC_GROUP* a, const EC_GROUP* b, BN_CTX* ctx);

	EC_GROUP* EC_GROUP_new_curve_GFp(const BIGNUM* p, const BIGNUM* a,
		const BIGNUM* b, BN_CTX* ctx);
# ifndef OPENSSL_NO_EC2M
	EC_GROUP* EC_GROUP_new_curve_GF2m(const BIGNUM* p, const BIGNUM* a,
		const BIGNUM* b, BN_CTX* ctx);
# endif

	EC_GROUP* EC_GROUP_new_by_curve_name(int nid);

	EC_GROUP* EC_GROUP_new_from_ecparameters(const ECPARAMETERS* params);

	ECPARAMETERS* EC_GROUP_get_ecparameters(const EC_GROUP* group,
		ECPARAMETERS* params);

	EC_GROUP* EC_GROUP_new_from_ecpkparameters(const ECPKPARAMETERS* params);

	ECPKPARAMETERS* EC_GROUP_get_ecpkparameters(const EC_GROUP* group,
		ECPKPARAMETERS* params);

	typedef struct {
		int nid;
		const char* comment;
	} EC_builtin_curve;

	size_t EC_get_builtin_curves(EC_builtin_curve* r, size_t nitems);

	const char* EC_curve_nid2nist(int nid);
	int EC_curve_nist2nid(const char* name);

	EC_POINT* EC_POINT_new(const EC_GROUP* group);

	void EC_POINT_free(EC_POINT* point);

	void EC_POINT_clear_free(EC_POINT* point);

	int EC_POINT_copy(EC_POINT* dst, const EC_POINT* src);

	EC_POINT* EC_POINT_dup(const EC_POINT* src, const EC_GROUP* group);

	const EC_METHOD* EC_POINT_method_of(const EC_POINT* point);

	int EC_POINT_set_to_infinity(const EC_GROUP* group, EC_POINT* point);

	int EC_POINT_set_Jprojective_coordinates_GFp(const EC_GROUP* group,
		EC_POINT* p, const BIGNUM* x,
		const BIGNUM* y, const BIGNUM* z,
		BN_CTX* ctx);

	int EC_POINT_get_Jprojective_coordinates_GFp(const EC_GROUP* group,
		const EC_POINT* p, BIGNUM* x,
		BIGNUM* y, BIGNUM* z,
		BN_CTX* ctx);

	int EC_POINT_set_affine_coordinates(const EC_GROUP* group, EC_POINT* p,
		const BIGNUM* x, const BIGNUM* y,
		BN_CTX* ctx);

	int EC_POINT_get_affine_coordinates(const EC_GROUP* group, const EC_POINT* p,
		BIGNUM* x, BIGNUM* y, BN_CTX* ctx);

	DEPRECATEDIN_1_2_0(int EC_POINT_set_affine_coordinates_GFp(const EC_GROUP* group,
		EC_POINT* p,
		const BIGNUM* x,
		const BIGNUM* y,
		BN_CTX* ctx))

		DEPRECATEDIN_1_2_0(int EC_POINT_get_affine_coordinates_GFp(const EC_GROUP* group,
			const EC_POINT* p,
			BIGNUM* x,
			BIGNUM* y,
			BN_CTX* ctx))

		int EC_POINT_set_compressed_coordinates(const EC_GROUP* group, EC_POINT* p,
			const BIGNUM* x, int y_bit,
			BN_CTX* ctx);

	DEPRECATEDIN_1_2_0(int EC_POINT_set_compressed_coordinates_GFp(const EC_GROUP* group,
		EC_POINT* p,
		const BIGNUM* x,
		int y_bit,
		BN_CTX* ctx))
# ifndef OPENSSL_NO_EC2M
		DEPRECATEDIN_1_2_0(int EC_POINT_set_affine_coordinates_GF2m(const EC_GROUP* group,
			EC_POINT* p,
			const BIGNUM* x,
			const BIGNUM* y,
			BN_CTX* ctx))

		DEPRECATEDIN_1_2_0(int EC_POINT_get_affine_coordinates_GF2m(const EC_GROUP* group,
			const EC_POINT* p,
			BIGNUM* x,
			BIGNUM* y,
			BN_CTX* ctx))

		DEPRECATEDIN_1_2_0(int EC_POINT_set_compressed_coordinates_GF2m(const EC_GROUP* group,
			EC_POINT* p,
			const BIGNUM* x,
			int y_bit,
			BN_CTX* ctx))
# endif
		size_t EC_POINT_point2oct(const EC_GROUP* group, const EC_POINT* p,
			point_conversion_form_t form,
			unsigned char* buf, size_t len, BN_CTX* ctx);

	int EC_POINT_oct2point(const EC_GROUP* group, EC_POINT* p,
		const unsigned char* buf, size_t len, BN_CTX* ctx);

	size_t EC_POINT_point2buf(const EC_GROUP* group, const EC_POINT* point,
		point_conversion_form_t form,
		unsigned char** pbuf, BN_CTX* ctx);

	BIGNUM* EC_POINT_point2bn(const EC_GROUP*, const EC_POINT*,
		point_conversion_form_t form, BIGNUM*, BN_CTX*);
	EC_POINT* EC_POINT_bn2point(const EC_GROUP*, const BIGNUM*,
		EC_POINT*, BN_CTX*);
	char* EC_POINT_point2hex(const EC_GROUP*, const EC_POINT*,
		point_conversion_form_t form, BN_CTX*);
	EC_POINT* EC_POINT_hex2point(const EC_GROUP*, const char*,
		EC_POINT*, BN_CTX*);

	int EC_POINT_add(const EC_GROUP* group, EC_POINT* r, const EC_POINT* a,
		const EC_POINT* b, BN_CTX* ctx);

	int EC_POINT_dbl(const EC_GROUP* group, EC_POINT* r, const EC_POINT* a,
		BN_CTX* ctx);

	int EC_POINT_invert(const EC_GROUP* group, EC_POINT* a, BN_CTX* ctx);

	int EC_POINT_is_at_infinity(const EC_GROUP* group, const EC_POINT* p);

	int EC_POINT_is_on_curve(const EC_GROUP* group, const EC_POINT* point,
		BN_CTX* ctx);

	int EC_POINT_cmp(const EC_GROUP* group, const EC_POINT* a, const EC_POINT* b,
		BN_CTX* ctx);

	int EC_POINT_make_affine(const EC_GROUP* group, EC_POINT* point, BN_CTX* ctx);
	int EC_POINTs_make_affine(const EC_GROUP* group, size_t num,
		EC_POINT* points[], BN_CTX* ctx);

	int EC_POINTs_mul(const EC_GROUP* group, EC_POINT* r, const BIGNUM* n,
		size_t num, const EC_POINT* p[], const BIGNUM* m[],
		BN_CTX* ctx);

	int EC_POINT_mul(const EC_GROUP* group, EC_POINT* r, const BIGNUM* n,
		const EC_POINT* q, const BIGNUM* m, BN_CTX* ctx);

	int EC_GROUP_precompute_mult(EC_GROUP* group, BN_CTX* ctx);

	int EC_GROUP_have_precompute_mult(const EC_GROUP* group);

	DECLARE_ASN1_ITEM(ECPKPARAMETERS)
		DECLARE_ASN1_ALLOC_FUNCTIONS(ECPKPARAMETERS)
		DECLARE_ASN1_ITEM(ECPARAMETERS)
		DECLARE_ASN1_ALLOC_FUNCTIONS(ECPARAMETERS)

		int EC_GROUP_get_basis_type(const EC_GROUP*);
# ifndef OPENSSL_NO_EC2M
	int EC_GROUP_get_trinomial_basis(const EC_GROUP*, unsigned int* k);
	int EC_GROUP_get_pentanomial_basis(const EC_GROUP*, unsigned int* k1,
		unsigned int* k2, unsigned int* k3);
# endif

# define OPENSSL_EC_EXPLICIT_CURVE  0x000
# define OPENSSL_EC_NAMED_CURVE     0x001

	EC_GROUP* d2i_ECPKParameters(EC_GROUP**, const unsigned char** in, long len);
	int i2d_ECPKParameters(const EC_GROUP*, unsigned char** out);

# define d2i_ECPKParameters_bio(bp,x) ASN1_d2i_bio_of(EC_GROUP,NULL,d2i_ECPKParameters,bp,x)
# define i2d_ECPKParameters_bio(bp,x) ASN1_i2d_bio_of_const(EC_GROUP,i2d_ECPKParameters,bp,x)
# define d2i_ECPKParameters_fp(fp,x) (EC_GROUP *)ASN1_d2i_fp(NULL, \
                (char *(*)())d2i_ECPKParameters,(fp),(unsigned char **)(x))
# define i2d_ECPKParameters_fp(fp,x) ASN1_i2d_fp(i2d_ECPKParameters,(fp), \
                (unsigned char *)(x))

	int ECPKParameters_print(BIO* bp, const EC_GROUP* x, int off);
# ifndef OPENSSL_NO_STDIO
	int ECPKParameters_print_fp(FILE* fp, const EC_GROUP* x, int off);
# endif

# define EC_PKEY_NO_PARAMETERS   0x001
# define EC_PKEY_NO_PUBKEY       0x002

# define EC_FLAG_NON_FIPS_ALLOW  0x1
# define EC_FLAG_FIPS_CHECKED    0x2
# define EC_FLAG_COFACTOR_ECDH   0x1000

	EC_KEY* EC_KEY_new(void);

	int EC_KEY_get_flags(const EC_KEY* key);

	void EC_KEY_set_flags(EC_KEY* key, int flags);

	void EC_KEY_clear_flags(EC_KEY* key, int flags);

	int EC_KEY_decoded_from_explicit_params(const EC_KEY* key);

	EC_KEY* EC_KEY_new_by_curve_name(int nid);

	void EC_KEY_free(EC_KEY* key);

	EC_KEY* EC_KEY_copy(EC_KEY* dst, const EC_KEY* src);

	EC_KEY* EC_KEY_dup(const EC_KEY* src);

	int EC_KEY_up_ref(EC_KEY* key);

	ENGINE* EC_KEY_get0_engine(const EC_KEY* eckey);

	const EC_GROUP* EC_KEY_get0_group(const EC_KEY* key);

	int EC_KEY_set_group(EC_KEY* key, const EC_GROUP* group);

	const BIGNUM* EC_KEY_get0_private_key(const EC_KEY* key);

	int EC_KEY_set_private_key(EC_KEY* key, const BIGNUM* prv);

	const EC_POINT* EC_KEY_get0_public_key(const EC_KEY* key);

	int EC_KEY_set_public_key(EC_KEY* key, const EC_POINT* pub);

	unsigned EC_KEY_get_enc_flags(const EC_KEY* key);
	void EC_KEY_set_enc_flags(EC_KEY* eckey, unsigned int flags);
	point_conversion_form_t EC_KEY_get_conv_form(const EC_KEY* key);
	void EC_KEY_set_conv_form(EC_KEY* eckey, point_conversion_form_t cform);

#define EC_KEY_get_ex_new_index(l, p, newf, dupf, freef) \
    CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_EC_KEY, l, p, newf, dupf, freef)
	int EC_KEY_set_ex_data(EC_KEY* key, int idx, void* arg);
	void* EC_KEY_get_ex_data(const EC_KEY* key, int idx);

	void EC_KEY_set_asn1_flag(EC_KEY* eckey, int asn1_flag);

	int EC_KEY_precompute_mult(EC_KEY* key, BN_CTX* ctx);

	int EC_KEY_generate_key(EC_KEY* key);

	int EC_KEY_check_key(const EC_KEY* key);

	int EC_KEY_can_sign(const EC_KEY* eckey);

	int EC_KEY_set_public_key_affine_coordinates(EC_KEY* key, BIGNUM* x,
		BIGNUM* y);

	size_t EC_KEY_key2buf(const EC_KEY* key, point_conversion_form_t form,
		unsigned char** pbuf, BN_CTX* ctx);

	int EC_KEY_oct2key(EC_KEY* key, const unsigned char* buf, size_t len,
		BN_CTX* ctx);

	int EC_KEY_oct2priv(EC_KEY* key, const unsigned char* buf, size_t len);

	size_t EC_KEY_priv2oct(const EC_KEY* key, unsigned char* buf, size_t len);

	size_t EC_KEY_priv2buf(const EC_KEY* eckey, unsigned char** pbuf);

	EC_KEY* d2i_ECPrivateKey(EC_KEY** key, const unsigned char** in, long len);

	int i2d_ECPrivateKey(EC_KEY* key, unsigned char** out);

	EC_KEY* d2i_ECParameters(EC_KEY** key, const unsigned char** in, long len);

	int i2d_ECParameters(EC_KEY* key, unsigned char** out);

	EC_KEY* o2i_ECPublicKey(EC_KEY** key, const unsigned char** in, long len);

	int i2o_ECPublicKey(const EC_KEY* key, unsigned char** out);

	int ECParameters_print(BIO* bp, const EC_KEY* key);

	int EC_KEY_print(BIO* bp, const EC_KEY* key, int off);

# ifndef OPENSSL_NO_STDIO
	int ECParameters_print_fp(FILE* fp, const EC_KEY* key);

	int EC_KEY_print_fp(FILE* fp, const EC_KEY* key, int off);

# endif

	const EC_KEY_METHOD* EC_KEY_OpenSSL(void);
	const EC_KEY_METHOD* EC_KEY_get_default_method(void);
	void EC_KEY_set_default_method(const EC_KEY_METHOD* meth);
	const EC_KEY_METHOD* EC_KEY_get_method(const EC_KEY* key);
	int EC_KEY_set_method(EC_KEY* key, const EC_KEY_METHOD* meth);
	EC_KEY* EC_KEY_new_method(ENGINE* engine);

	int ECDH_KDF_X9_62(unsigned char* out, size_t outlen,
		const unsigned char* Z, size_t Zlen,
		const unsigned char* sinfo, size_t sinfolen,
		const EVP_MD* md);

	int ECDH_compute_key(void* out, size_t outlen, const EC_POINT* pub_key,
		const EC_KEY* ecdh,
		void* (*KDF) (const void* in, size_t inlen,
			void* out, size_t* outlen));

	typedef struct ECDSA_SIG_st ECDSA_SIG;

	ECDSA_SIG* ECDSA_SIG_new(void);

	void ECDSA_SIG_free(ECDSA_SIG* sig);

	int i2d_ECDSA_SIG(const ECDSA_SIG* sig, unsigned char** pp);

	ECDSA_SIG* d2i_ECDSA_SIG(ECDSA_SIG** sig, const unsigned char** pp, long len);

	void ECDSA_SIG_get0(const ECDSA_SIG* sig, const BIGNUM** pr, const BIGNUM** ps);

	const BIGNUM* ECDSA_SIG_get0_r(const ECDSA_SIG* sig);

	const BIGNUM* ECDSA_SIG_get0_s(const ECDSA_SIG* sig);

	int ECDSA_SIG_set0(ECDSA_SIG* sig, BIGNUM* r, BIGNUM* s);

	ECDSA_SIG* ECDSA_do_sign(const unsigned char* dgst, int dgst_len,
		EC_KEY* eckey);

	ECDSA_SIG* ECDSA_do_sign_ex(const unsigned char* dgst, int dgstlen,
		const BIGNUM* kinv, const BIGNUM* rp,
		EC_KEY* eckey);

	int ECDSA_do_verify(const unsigned char* dgst, int dgst_len,
		const ECDSA_SIG* sig, EC_KEY* eckey);

	int ECDSA_sign_setup(EC_KEY* eckey, BN_CTX* ctx, BIGNUM** kinv, BIGNUM** rp);

	int ECDSA_sign(int type, const unsigned char* dgst, int dgstlen,
		unsigned char* sig, unsigned int* siglen, EC_KEY* eckey);

	int ECDSA_sign_ex(int type, const unsigned char* dgst, int dgstlen,
		unsigned char* sig, unsigned int* siglen,
		const BIGNUM* kinv, const BIGNUM* rp, EC_KEY* eckey);

	int ECDSA_verify(int type, const unsigned char* dgst, int dgstlen,
		const unsigned char* sig, int siglen, EC_KEY* eckey);

	int ECDSA_size(const EC_KEY* eckey);

	EC_KEY_METHOD* EC_KEY_METHOD_new(const EC_KEY_METHOD* meth);
	void EC_KEY_METHOD_free(EC_KEY_METHOD* meth);
	void EC_KEY_METHOD_set_init(EC_KEY_METHOD* meth,
		int (*init)(EC_KEY* key),
		void (*finish)(EC_KEY* key),
		int (*copy)(EC_KEY* dest, const EC_KEY* src),
		int (*set_group)(EC_KEY* key, const EC_GROUP* grp),
		int (*set_private)(EC_KEY* key,
			const BIGNUM* priv_key),
		int (*set_public)(EC_KEY* key,
			const EC_POINT* pub_key));

	void EC_KEY_METHOD_set_keygen(EC_KEY_METHOD* meth,
		int (*keygen)(EC_KEY* key));

	void EC_KEY_METHOD_set_compute_key(EC_KEY_METHOD* meth,
		int (*ckey)(unsigned char** psec,
			size_t* pseclen,
			const EC_POINT* pub_key,
			const EC_KEY* ecdh));

	void EC_KEY_METHOD_set_sign(EC_KEY_METHOD* meth,
		int (*sign)(int type, const unsigned char* dgst,
			int dlen, unsigned char* sig,
			unsigned int* siglen,
			const BIGNUM* kinv, const BIGNUM* r,
			EC_KEY* eckey),
		int (*sign_setup)(EC_KEY* eckey, BN_CTX* ctx_in,
			BIGNUM** kinvp, BIGNUM** rp),
		ECDSA_SIG* (*sign_sig)(const unsigned char* dgst,
			int dgst_len,
			const BIGNUM* in_kinv,
			const BIGNUM* in_r,
			EC_KEY* eckey));

	void EC_KEY_METHOD_set_verify(EC_KEY_METHOD* meth,
		int (*verify)(int type, const unsigned
			char* dgst, int dgst_len,
			const unsigned char* sigbuf,
			int sig_len, EC_KEY* eckey),
		int (*verify_sig)(const unsigned char* dgst,
			int dgst_len,
			const ECDSA_SIG* sig,
			EC_KEY* eckey));

	void EC_KEY_METHOD_get_init(const EC_KEY_METHOD* meth,
		int (**pinit)(EC_KEY* key),
		void (**pfinish)(EC_KEY* key),
		int (**pcopy)(EC_KEY* dest, const EC_KEY* src),
		int (**pset_group)(EC_KEY* key,
			const EC_GROUP* grp),
		int (**pset_private)(EC_KEY* key,
			const BIGNUM* priv_key),
		int (**pset_public)(EC_KEY* key,
			const EC_POINT* pub_key));

	void EC_KEY_METHOD_get_keygen(const EC_KEY_METHOD* meth,
		int (**pkeygen)(EC_KEY* key));

	void EC_KEY_METHOD_get_compute_key(const EC_KEY_METHOD* meth,
		int (**pck)(unsigned char** psec,
			size_t* pseclen,
			const EC_POINT* pub_key,
			const EC_KEY* ecdh));

	void EC_KEY_METHOD_get_sign(const EC_KEY_METHOD* meth,
		int (**psign)(int type, const unsigned char* dgst,
			int dlen, unsigned char* sig,
			unsigned int* siglen,
			const BIGNUM* kinv, const BIGNUM* r,
			EC_KEY* eckey),
		int (**psign_setup)(EC_KEY* eckey, BN_CTX* ctx_in,
			BIGNUM** kinvp, BIGNUM** rp),
		ECDSA_SIG* (**psign_sig)(const unsigned char* dgst,
			int dgst_len,
			const BIGNUM* in_kinv,
			const BIGNUM* in_r,
			EC_KEY* eckey));

	void EC_KEY_METHOD_get_verify(const EC_KEY_METHOD* meth,
		int (**pverify)(int type, const unsigned
			char* dgst, int dgst_len,
			const unsigned char* sigbuf,
			int sig_len, EC_KEY* eckey),
		int (**pverify_sig)(const unsigned char* dgst,
			int dgst_len,
			const ECDSA_SIG* sig,
			EC_KEY* eckey));

# define ECParameters_dup(x) ASN1_dup_of(EC_KEY,i2d_ECParameters,d2i_ECParameters,x)

# ifndef __cplusplus
#  if defined(__SUNPRO_C)
#   if __SUNPRO_C >= 0x520
#    pragma error_messages (default,E_ARRAY_OF_INCOMPLETE_NONAME,E_ARRAY_OF_INCOMPLETE)
#   endif
#  endif
# endif

# define EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC, \
                                EVP_PKEY_OP_PARAMGEN|EVP_PKEY_OP_KEYGEN, \
                                EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID, nid, NULL)

# define EVP_PKEY_CTX_set_ec_param_enc(ctx, flag) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC, \
                                EVP_PKEY_OP_PARAMGEN|EVP_PKEY_OP_KEYGEN, \
                                EVP_PKEY_CTRL_EC_PARAM_ENC, flag, NULL)

# define EVP_PKEY_CTX_set_ecdh_cofactor_mode(ctx, flag) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC, \
                                EVP_PKEY_OP_DERIVE, \
                                EVP_PKEY_CTRL_EC_ECDH_COFACTOR, flag, NULL)

# define EVP_PKEY_CTX_get_ecdh_cofactor_mode(ctx) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC, \
                                EVP_PKEY_OP_DERIVE, \
                                EVP_PKEY_CTRL_EC_ECDH_COFACTOR, -2, NULL)

# define EVP_PKEY_CTX_set_ecdh_kdf_type(ctx, kdf) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC, \
                                EVP_PKEY_OP_DERIVE, \
                                EVP_PKEY_CTRL_EC_KDF_TYPE, kdf, NULL)

# define EVP_PKEY_CTX_get_ecdh_kdf_type(ctx) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC, \
                                EVP_PKEY_OP_DERIVE, \
                                EVP_PKEY_CTRL_EC_KDF_TYPE, -2, NULL)

# define EVP_PKEY_CTX_set_ecdh_kdf_md(ctx, md) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC, \
                                EVP_PKEY_OP_DERIVE, \
                                EVP_PKEY_CTRL_EC_KDF_MD, 0, (void *)(md))

# define EVP_PKEY_CTX_get_ecdh_kdf_md(ctx, pmd) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC, \
                                EVP_PKEY_OP_DERIVE, \
                                EVP_PKEY_CTRL_GET_EC_KDF_MD, 0, (void *)(pmd))

# define EVP_PKEY_CTX_set_ecdh_kdf_outlen(ctx, len) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC, \
                                EVP_PKEY_OP_DERIVE, \
                                EVP_PKEY_CTRL_EC_KDF_OUTLEN, len, NULL)

# define EVP_PKEY_CTX_get_ecdh_kdf_outlen(ctx, plen) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC, \
                                EVP_PKEY_OP_DERIVE, \
                                EVP_PKEY_CTRL_GET_EC_KDF_OUTLEN, 0, \
                                (void *)(plen))

# define EVP_PKEY_CTX_set0_ecdh_kdf_ukm(ctx, p, plen) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC, \
                                EVP_PKEY_OP_DERIVE, \
                                EVP_PKEY_CTRL_EC_KDF_UKM, plen, (void *)(p))

# define EVP_PKEY_CTX_get0_ecdh_kdf_ukm(ctx, p) \
        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC, \
                                EVP_PKEY_OP_DERIVE, \
                                EVP_PKEY_CTRL_GET_EC_KDF_UKM, 0, (void *)(p))

# define EVP_PKEY_CTX_set1_id(ctx, id, id_len) \
        EVP_PKEY_CTX_ctrl(ctx, -1, -1, \
                                EVP_PKEY_CTRL_SET1_ID, (int)id_len, (void*)(id))

# define EVP_PKEY_CTX_get1_id(ctx, id) \
        EVP_PKEY_CTX_ctrl(ctx, -1, -1, \
                                EVP_PKEY_CTRL_GET1_ID, 0, (void*)(id))

# define EVP_PKEY_CTX_get1_id_len(ctx, id_len) \
        EVP_PKEY_CTX_ctrl(ctx, -1, -1, \
                                EVP_PKEY_CTRL_GET1_ID_LEN, 0, (void*)(id_len))

# define EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID             (EVP_PKEY_ALG_CTRL + 1)
# define EVP_PKEY_CTRL_EC_PARAM_ENC                      (EVP_PKEY_ALG_CTRL + 2)
# define EVP_PKEY_CTRL_EC_ECDH_COFACTOR                  (EVP_PKEY_ALG_CTRL + 3)
# define EVP_PKEY_CTRL_EC_KDF_TYPE                       (EVP_PKEY_ALG_CTRL + 4)
# define EVP_PKEY_CTRL_EC_KDF_MD                         (EVP_PKEY_ALG_CTRL + 5)
# define EVP_PKEY_CTRL_GET_EC_KDF_MD                     (EVP_PKEY_ALG_CTRL + 6)
# define EVP_PKEY_CTRL_EC_KDF_OUTLEN                     (EVP_PKEY_ALG_CTRL + 7)
# define EVP_PKEY_CTRL_GET_EC_KDF_OUTLEN                 (EVP_PKEY_ALG_CTRL + 8)
# define EVP_PKEY_CTRL_EC_KDF_UKM                        (EVP_PKEY_ALG_CTRL + 9)
# define EVP_PKEY_CTRL_GET_EC_KDF_UKM                    (EVP_PKEY_ALG_CTRL + 10)
# define EVP_PKEY_CTRL_SET1_ID                           (EVP_PKEY_ALG_CTRL + 11)
# define EVP_PKEY_CTRL_GET1_ID                           (EVP_PKEY_ALG_CTRL + 12)
# define EVP_PKEY_CTRL_GET1_ID_LEN                       (EVP_PKEY_ALG_CTRL + 13)
# define EVP_PKEY_ECDH_KDF_NONE                          1
# define EVP_PKEY_ECDH_KDF_X9_63                         2
# define EVP_PKEY_ECDH_KDF_X9_62   EVP_PKEY_ECDH_KDF_X9_63

#  ifdef  __cplusplus
}
#  endif
# endif
#endif
