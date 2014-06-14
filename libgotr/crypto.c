#include "crypto.h"

#define CURVE "Ed25519"



// --- HASHING ---

/**
 * Hash block of given size.
 *
 * @param block the data to #GNUNET_CRYPTO_hash, length is given as a second argument
 * @param size the length of the data to #GNUNET_CRYPTO_hash in @a block
 * @param ret pointer to where to write the hashcode
 */
void
gotr_hash (const void *block,
                    size_t size,
                    struct gotr_HashCode *ret)
{
  gcry_md_hash_buffer (GCRY_MD_SHA512, ret, block, size);
}



// --- MPI ---

/**
 * If target != size, move @a target bytes to the end of the size-sized
 * buffer and zero out the first @a target - @a size bytes.
 *
 * @param buf original buffer
 * @param size number of bytes in @a buf
 * @param target target size of the buffer
 */
static void
adjust (void *buf,
	size_t size,
	size_t target)
{
  char *p = buf;

  if (size < target)
  {
    memmove (&p[target - size], buf, size);
    memset (buf, 0, target - size);
  }
}

/**
 * Output the given MPI value to the given buffer in
 * network byte order.
 * The MPI @a val may not be negative.
 *
 * @param buf where to output to
 * @param size number of bytes in @a buf
 * @param val value to write to @a buf
 */
void
gotr_mpi_print_unsigned (void *buf,
                                  size_t size,
                                  gcry_mpi_t val)
{
  size_t rsize;

  if (gcry_mpi_get_flag (val, GCRYMPI_FLAG_OPAQUE))
  {
    /* Store opaque MPIs left aligned into the buffer.  */
    unsigned int nbits;
    const void *p;

    p = gcry_mpi_get_opaque (val, &nbits);
    //GNUNET_assert (p);
    rsize = (nbits+7)/8;
    if (rsize > size)
      rsize = size;
    memcpy (buf, p, rsize);
    if (rsize < size)
      memset (buf+rsize, 0, size - rsize);
  }
  else
  {
    /* Store regular MPIs as unsigned integers right aligned into
       the buffer.  */
    rsize = size;
    /*GNUNET_assert (0 ==*/
                   gcry_mpi_print (GCRYMPI_FMT_USG, buf, rsize, &rsize,
                                   val);//);
    adjust (buf, rsize, size);
  }
}

/**
 * Convert data buffer into MPI value.
 * The buffer is interpreted as network
 * byte order, unsigned integer.
 *
 * @param result where to store MPI value (allocated)
 * @param data raw data (GCRYMPI_FMT_USG)
 * @param size number of bytes in @a data
 */
void
gotr_mpi_scan_unsigned (gcry_mpi_t *result,
                                 const void *data,
                                 size_t size)
{
  int rc;

  if (0 != (rc = gcry_mpi_scan (result,
				GCRYMPI_FMT_USG,
				data, size, &size)))
  {
    //LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_mpi_scan", rc);
    //GNUNET_assert (0);
  }
}


// --- EdDSA ---

/**
 * Extract values from an S-expression.
 *
 * @param array where to store the result(s)
 * @param sexp S-expression to parse
 * @param topname top-level name in the S-expression that is of interest
 * @param elems names of the elements to extract
 * @return 0 on success
 */
static int
key_from_sexp (gcry_mpi_t * array, gcry_sexp_t sexp, const char *topname,
               const char *elems)
{
  gcry_sexp_t list;
  gcry_sexp_t l2;
  const char *s;
  unsigned int i;
  unsigned int idx;

  list = gcry_sexp_find_token (sexp, topname, 0);
  if (! list)
    return 1;
  l2 = gcry_sexp_cadr (list);
  gcry_sexp_release (list);
  list = l2;
  if (! list)
    return 2;

  idx = 0;
  for (s = elems; *s; s++, idx++)
  {
    l2 = gcry_sexp_find_token (list, s, 1);
    if (! l2)
    {
      for (i = 0; i < idx; i++)
      {
        gcry_free (array[i]);
        array[i] = NULL;
      }
      gcry_sexp_release (list);
      return 3;                 /* required parameter not found */
    }
    array[idx] = gcry_sexp_nth_mpi (l2, 1, GCRYMPI_FMT_USG);
    gcry_sexp_release (l2);
    if (! array[idx])
    {
      for (i = 0; i < idx; i++)
      {
        gcry_free (array[i]);
        array[i] = NULL;
      }
      gcry_sexp_release (list);
      return 4;                 /* required parameter is invalid */
    }
  }
  gcry_sexp_release (list);
  return 0;
}

/**
 * Convert the given private key from the network format to the
 * S-expression that can be used by libgcrypt.
 *
 * @param priv private key to decode
 * @return NULL on error
 */
static gcry_sexp_t
decode_private_eddsa_key (const struct gotr_EddsaPrivateKey *priv)
{
  gcry_sexp_t result;
  int rc;

  rc = gcry_sexp_build (&result, NULL,
			"(private-key(ecc(curve \"" CURVE "\")"
                        "(flags eddsa)(d %b)))",
			(int)sizeof (priv->d), priv->d);
  if (0 != rc)
  {
    //LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_sexp_build", rc);
    //GNUNET_assert (0);
  }
#if EXTRA_CHECKS
  if (0 != (rc = gcry_pk_testkey (result)))
  {
    //LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_pk_testkey", rc);
    //GNUNET_assert (0);
  }
#endif
  return result;
}

/**
 * Extract the public key for the given private key.
 *
 * @param priv the private key
 * @param pub where to write the public key
 */
void
gotr_eddsa_key_get_public (const struct gotr_EddsaPrivateKey *priv,
                                    struct gotr_EddsaPublicKey *pub)
{
  gcry_sexp_t sexp;
  gcry_ctx_t ctx;
  gcry_mpi_t q;

  sexp = decode_private_eddsa_key (priv);
  //GNUNET_assert (NULL != sexp);
  /*GNUNET_assert (0 == */gcry_mpi_ec_new (&ctx, sexp, NULL);//);
  gcry_sexp_release (sexp);
  q = gcry_mpi_ec_get_mpi ("q@eddsa", ctx, 0);
  //GNUNET_assert (q);
  gotr_mpi_print_unsigned (pub->q_y, sizeof (pub->q_y), q);
  gcry_mpi_release (q);
  gcry_ctx_release (ctx);
}

/**
 * @ingroup crypto
 * Clear memory that was used to store a private key.
 *
 * @param pk location of the key
 */
void
gotr_eddsa_key_clear (struct gotr_EddsaPrivateKey *pk)
{
  memset (pk, 0, sizeof (struct gotr_EddsaPrivateKey));
}

/**
 * Create a new private key. Caller must free return value.
 *
 * @return fresh private key
 */
struct gotr_EddsaPrivateKey *
gotr_eddsa_key_create ()
{
  struct gotr_EddsaPrivateKey *priv;
  gcry_sexp_t priv_sexp;
  gcry_sexp_t s_keyparam;
  gcry_mpi_t d;
  int rc;

  if (0 != (rc = gcry_sexp_build (&s_keyparam, NULL,
                                  "(genkey(ecc(curve \"" CURVE "\")"
                                  "(flags eddsa)))")))
  {
    //LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_sexp_build", rc);
    return NULL;
  }
  if (0 != (rc = gcry_pk_genkey (&priv_sexp, s_keyparam)))
  {
    //LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_pk_genkey", rc);
    gcry_sexp_release (s_keyparam);
    return NULL;
  }
  gcry_sexp_release (s_keyparam);
#if EXTRA_CHECKS
  if (0 != (rc = gcry_pk_testkey (priv_sexp)))
  {
    //LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_pk_testkey", rc);
    gcry_sexp_release (priv_sexp);
    return NULL;
  }
#endif
  if (0 != (rc = key_from_sexp (&d, priv_sexp, "private-key", "d")))
  {
    //LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "key_from_sexp", rc);
    gcry_sexp_release (priv_sexp);
    return NULL;
  }
  gcry_sexp_release (priv_sexp);
  priv = malloc(sizeof(struct gotr_EddsaPrivateKey));
  gotr_mpi_print_unsigned (priv->d, sizeof (priv->d), d);
  gcry_mpi_release (d);
  return priv;
}

/**
 * Convert the data specified in the given purpose argument to an
 * S-expression suitable for signature operations.
 *
 * @param purpose data to convert
 * @return converted s-expression
 */
static gcry_sexp_t
data_to_eddsa_value (const struct gotr_EccSignaturePurpose *purpose)
{
  struct gotr_HashCode hc;
  gcry_sexp_t data;
  int rc;

  gotr_hash (purpose, ntohl (purpose->size), &hc);
  if (0 != (rc = gcry_sexp_build (&data, NULL,
				  "(data(flags eddsa)(hash-algo %s)(value %b))",
				  "sha512",
				  (int)sizeof (hc), &hc)))
  {
    //LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_sexp_build", rc);
    return NULL;
  }
  return data;
}

/**
 * Sign a given block.
 *
 * @param priv private key to use for the signing
 * @param purpose what to sign (size, purpose)
 * @param sig where to write the signature
 * @return #GNUNET_SYSERR on error, #GNUNET_OK on success
 */
int
gotr_eddsa_sign (const struct gotr_EddsaPrivateKey *priv,
                          const struct gotr_EccSignaturePurpose *purpose,
                          struct gotr_EddsaSignature *sig)
{
  gcry_sexp_t priv_sexp;
  gcry_sexp_t sig_sexp;
  gcry_sexp_t data;
  int rc;
  gcry_mpi_t rs[2];

  priv_sexp = decode_private_eddsa_key (priv);
  data = data_to_eddsa_value (purpose);
  if (0 != (rc = gcry_pk_sign (&sig_sexp, data, priv_sexp)))
  {
    /*LOG (GNUNET_ERROR_TYPE_WARNING,
         _("EdDSA signing failed at %s:%d: %s\n"), __FILE__,
         __LINE__, gcry_strerror (rc));*/
    gcry_sexp_release (data);
    gcry_sexp_release (priv_sexp);
    //return GNUNET_SYSERR;
	return -1;
  }
  gcry_sexp_release (priv_sexp);
  gcry_sexp_release (data);

  /* extract 'r' and 's' values from sexpression 'sig_sexp' and store in
     'signature' */
  if (0 != (rc = key_from_sexp (rs, sig_sexp, "sig-val", "rs")))
  {
    //GNUNET_break (0);
    gcry_sexp_release (sig_sexp);
    //return GNUNET_SYSERR;
	return -1;
  }
  gcry_sexp_release (sig_sexp);
  gotr_mpi_print_unsigned (sig->r, sizeof (sig->r), rs[0]);
  gotr_mpi_print_unsigned (sig->s, sizeof (sig->s), rs[1]);
  gcry_mpi_release (rs[0]);
  gcry_mpi_release (rs[1]);
  //return GNUNET_OK;
  return 1;
}

/**
 * Verify signature.
 *
 * @param purpose what is the purpose that the signature should have?
 * @param validate block to validate (size, purpose, data)
 * @param sig signature that is being validated
 * @param pub public key of the signer
 * @returns #GNUNET_OK if ok, #GNUNET_SYSERR if invalid
 */
int
gotr_eddsa_verify (uint32_t purpose,
                            const struct gotr_EccSignaturePurpose *validate,
                            const struct gotr_EddsaSignature *sig,
                            const struct gotr_EddsaPublicKey *pub)
{
  gcry_sexp_t data;
  gcry_sexp_t sig_sexpr;
  gcry_sexp_t pub_sexpr;
  int rc;

  if (purpose != ntohl (validate->purpose)) {
  	//return GNUNET_SYSERR;       /* purpose mismatch */
	return -1;
  }
    

  /* build s-expression for signature */
  if (0 != (rc = gcry_sexp_build (&sig_sexpr, NULL,
				  "(sig-val(eddsa(r %b)(s %b)))",
                                  (int)sizeof (sig->r), sig->r,
                                  (int)sizeof (sig->s), sig->s)))
  {
    //LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_sexp_build", rc);
    //return GNUNET_SYSERR;
	return -1;
  }
  data = data_to_eddsa_value (validate);
  if (0 != (rc = gcry_sexp_build (&pub_sexpr, NULL,
                                  "(public-key(ecc(curve " CURVE ")(q %b)))",
                                  (int)sizeof (pub->q_y), pub->q_y)))
  {
    gcry_sexp_release (data);
    gcry_sexp_release (sig_sexpr);
    //return GNUNET_SYSERR;
	return -1;
  }
  rc = gcry_pk_verify (sig_sexpr, data, pub_sexpr);
  gcry_sexp_release (pub_sexpr);
  gcry_sexp_release (data);
  gcry_sexp_release (sig_sexpr);
  if (0 != rc)
  {
    /*LOG (GNUNET_ERROR_TYPE_INFO,
         _("EdDSA signature verification failed at %s:%d: %s\n"), __FILE__,
         __LINE__, gcry_strerror (rc));*/
    //return GNUNET_SYSERR;
	return -1;
  }
  //return GNUNET_OK;
  return 1;
}



// --- ECDHE ---

/**
 * Convert the given private key from the network format to the
 * S-expression that can be used by libgcrypt.
 *
 * @param priv private key to decode
 * @return NULL on error
 */
static gcry_sexp_t
decode_private_ecdhe_key (const struct gotr_EcdhePrivateKey *priv)
{
  gcry_sexp_t result;
  int rc;

  rc = gcry_sexp_build (&result, NULL,
			"(private-key(ecc(curve \"" CURVE "\")"
                        "(d %b)))",
			(int)sizeof (priv->d), priv->d);
  if (0 != rc)
  {
    //LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_sexp_build", rc);
    //GNUNET_assert (0);
  }
#if EXTRA_CHECKS
  if (0 != (rc = gcry_pk_testkey (result)))
  {
    //LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_pk_testkey", rc);
    //GNUNET_assert (0);
  }
#endif
  return result;
}

/**
 * Extract the public key for the given private key.
 *
 * @param priv the private key
 * @param pub where to write the public key
 */
void
gotr_ecdhe_key_get_public (const struct gotr_EcdhePrivateKey *priv,
                                    struct gotr_EcdhePublicKey *pub)
{
  gcry_sexp_t sexp;
  gcry_ctx_t ctx;
  gcry_mpi_t q;

  sexp = decode_private_ecdhe_key (priv);
  //GNUNET_assert (NULL != sexp);
  /*GNUNET_assert (0 == */gcry_mpi_ec_new (&ctx, sexp, NULL);//);
  gcry_sexp_release (sexp);
  q = gcry_mpi_ec_get_mpi ("q@eddsa", ctx, 0);
  //GNUNET_assert (q);
  gotr_mpi_print_unsigned (pub->q_y, sizeof (pub->q_y), q);
  gcry_mpi_release (q);
  gcry_ctx_release (ctx);
}

/**
 * @ingroup crypto
 * Clear memory that was used to store a private key.
 *
 * @param pk location of the key
 */
void
gotr_ecdhe_key_clear (struct gotr_EcdhePrivateKey *pk)
{
  memset (pk, 0, sizeof (struct gotr_EcdhePrivateKey));
}

/**
 * Create a new private key. Caller must free return value.
 *
 * @return fresh private key
 */
struct gotr_EcdhePrivateKey *
gotr_ecdhe_key_create ()
{
  struct gotr_EcdhePrivateKey *priv;
  gcry_sexp_t priv_sexp;
  gcry_sexp_t s_keyparam;
  gcry_mpi_t d;
  int rc;

  if (0 != (rc = gcry_sexp_build (&s_keyparam, NULL,
                                  "(genkey(ecc(curve \"" CURVE "\")"
                                  "(flags)))")))
  {
    //LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_sexp_build", rc);
    return NULL;
  }
  if (0 != (rc = gcry_pk_genkey (&priv_sexp, s_keyparam)))
  {
    //LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_pk_genkey", rc);
    gcry_sexp_release (s_keyparam);
    return NULL;
  }
  gcry_sexp_release (s_keyparam);
#if EXTRA_CHECKS
  if (0 != (rc = gcry_pk_testkey (priv_sexp)))
  {
    //LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_pk_testkey", rc);
    gcry_sexp_release (priv_sexp);
    return NULL;
  }
#endif
  if (0 != (rc = key_from_sexp (&d, priv_sexp, "private-key", "d")))
  {
    //LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "key_from_sexp", rc);
    gcry_sexp_release (priv_sexp);
    return NULL;
  }
  gcry_sexp_release (priv_sexp);
  priv = malloc(sizeof(struct gotr_EcdhePrivateKey));
  gotr_mpi_print_unsigned (priv->d, sizeof (priv->d), d);
  gcry_mpi_release (d);
  return priv;
}

/**
 * Derive key material from a public and a private ECDHE key.
 *
 * @param priv private key to use for the ECDH (x)
 * @param pub public key to use for the ECDH (yG)
 * @param key_material where to write the key material (xyG)
 * @return #GNUNET_SYSERR on error, #GNUNET_OK on success
 */
int
gotr_ecc_ecdh (const struct gotr_EcdhePrivateKey *priv,
                        const struct gotr_EcdhePublicKey *pub,
                        struct gotr_HashCode *key_material)
{
  gcry_mpi_point_t result;
  gcry_mpi_point_t q;
  gcry_mpi_t d;
  gcry_ctx_t ctx;
  gcry_sexp_t pub_sexpr;
  gcry_mpi_t result_x;
  unsigned char xbuf[256 / 8];
  size_t rsize;

  /* first, extract the q = dP value from the public key */
  if (0 != gcry_sexp_build (&pub_sexpr, NULL,
                            "(public-key(ecc(curve " CURVE ")(q %b)))",
                            (int)sizeof (pub->q_y), pub->q_y)) {
                            	//return GNUNET_SYSERR;
								return -1;
                            }
    
  /*GNUNET_assert (0 == */gcry_mpi_ec_new (&ctx, pub_sexpr, NULL);//);
  gcry_sexp_release (pub_sexpr);
  q = gcry_mpi_ec_get_point ("q", ctx, 0);

  /* second, extract the d value from our private key */
  gotr_mpi_scan_unsigned (&d, priv->d, sizeof (priv->d));

  /* then call the 'multiply' function, to compute the product */
  result = gcry_mpi_point_new (0);
  gcry_mpi_ec_mul (result, d, q, ctx);
  gcry_mpi_point_release (q);
  gcry_mpi_release (d);

  /* finally, convert point to string for hashing */
  result_x = gcry_mpi_new (256);
  if (gcry_mpi_ec_get_affine (result_x, NULL, result, ctx))
  {
    //LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "get_affine failed", 0);
    gcry_mpi_point_release (result);
    gcry_ctx_release (ctx);
    //return GNUNET_SYSERR;
	return -1;
  }
  gcry_mpi_point_release (result);
  gcry_ctx_release (ctx);

  rsize = sizeof (xbuf);
  /*GNUNET_assert (! */gcry_mpi_get_flag (result_x, GCRYMPI_FLAG_OPAQUE);//);
  /* result_x can be negative here, so we do not use 'GNUNET_CRYPTO_mpi_print_unsigned'
     as that does not include the sign bit; x should be a 255-bit
     value, so with the sign it should fit snugly into the 256-bit
     xbuf */
  /*GNUNET_assert (0 ==*/
                 gcry_mpi_print (GCRYMPI_FMT_STD, xbuf, rsize, &rsize,
                                 result_x);//);
  gotr_hash (xbuf, rsize, key_material);
  gcry_mpi_release (result_x);
  //return GNUNET_OK;
  return 1;
}



// --- Symmetric ---

/**
 * Create a new SessionKey (for symmetric encryption).
 *
 * @param key session key to initialize
 */
void
gotr_symmetric_create_session_key (struct gotr_SymmetricSessionKey *key)
{
  gcry_randomize (key->aes_key,
                  gotr_AES_KEY_LENGTH,
                  GCRY_STRONG_RANDOM);
  gcry_randomize (key->twofish_key,
                  gotr_AES_KEY_LENGTH,
                  GCRY_STRONG_RANDOM);
}

/**
 * Initialize AES cipher.
 *
 * @param handle handle to initialize
 * @param sessionkey session key to use
 * @param iv initialization vector to use
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static int
setup_cipher_aes (gcry_cipher_hd_t *handle,
                  const struct gotr_SymmetricSessionKey *sessionkey,
                  const struct gotr_SymmetricInitializationVector *iv)
{
  int rc;

  /*GNUNET_assert (0 ==*/
                 gcry_cipher_open (handle, GCRY_CIPHER_AES256,
                                   GCRY_CIPHER_MODE_CFB, 0);//);
  rc = gcry_cipher_setkey (*handle,
                           sessionkey->aes_key,
                           sizeof (sessionkey->aes_key));
  //GNUNET_assert ((0 == rc) || ((char) rc == GPG_ERR_WEAK_KEY));
  rc = gcry_cipher_setiv (*handle,
                          iv->aes_iv,
                          sizeof (iv->aes_iv));
  //GNUNET_assert ((0 == rc) || ((char) rc == GPG_ERR_WEAK_KEY));
  //return GNUNET_OK;
  return 1;
}

/**
 * Initialize TWOFISH cipher.
 *
 * @param handle handle to initialize
 * @param sessionkey session key to use
 * @param iv initialization vector to use
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static int
setup_cipher_twofish (gcry_cipher_hd_t *handle,
                      const struct gotr_SymmetricSessionKey *sessionkey,
                      const struct gotr_SymmetricInitializationVector *iv)
{
  int rc;

  /*GNUNET_assert (0 ==*/
                 gcry_cipher_open (handle, GCRY_CIPHER_TWOFISH,
                                   GCRY_CIPHER_MODE_CFB, 0);//);
  rc = gcry_cipher_setkey (*handle,
                           sessionkey->twofish_key,
                           sizeof (sessionkey->twofish_key));
  //GNUNET_assert ((0 == rc) || ((char) rc == GPG_ERR_WEAK_KEY));
  rc = gcry_cipher_setiv (*handle,
                          iv->twofish_iv,
                          sizeof (iv->twofish_iv));
  //GNUNET_assert ((0 == rc) || ((char) rc == GPG_ERR_WEAK_KEY));
  //return GNUNET_OK;
  return 1;
}

/**
 * Encrypt a block with a symmetric session key.
 *
 * @param block the block to encrypt
 * @param size the size of the @a block
 * @param sessionkey the key used to encrypt
 * @param iv the initialization vector to use, use INITVALUE for streams
 * @param result the output parameter in which to store the encrypted result
 *               can be the same or overlap with @c block
 * @returns the size of the encrypted block, -1 for errors.
 *          Due to the use of CFB and therefore an effective stream cipher,
 *          this size should be the same as @c len.
 */
ssize_t
gotr_symmetric_encrypt (const void *block,
                                 size_t size,
                                 const struct gotr_SymmetricSessionKey *sessionkey,
                                 const struct gotr_SymmetricInitializationVector *iv,
                                 void *result)
{
  gcry_cipher_hd_t handle;
  char tmp[size];

  if (/*GNUNET_OK*/ 1 != setup_cipher_aes (&handle, sessionkey, iv))
    return -1;
  /*GNUNET_assert (0 == */gcry_cipher_encrypt (handle, tmp, size, block, size);//);
  gcry_cipher_close (handle);
  if (/*GNUNET_OK*/ 1 != setup_cipher_twofish (&handle, sessionkey, iv))
    return -1;
  /*GNUNET_assert (0 == */gcry_cipher_encrypt (handle, result, size, tmp, size);//);
  gcry_cipher_close (handle);
  memset (tmp, 0, sizeof (tmp));
  return size;
}


/**
 * Decrypt a given block with the session key.
 *
 * @param block the data to decrypt, encoded as returned by encrypt
 * @param size the size of the @a block to decrypt
 * @param sessionkey the key used to decrypt
 * @param iv the initialization vector to use, use INITVALUE for streams
 * @param result address to store the result at
 *               can be the same or overlap with @c block
 * @return -1 on failure, size of decrypted block on success.
 *         Due to the use of CFB and therefore an effective stream cipher,
 *         this size should be the same as @c size.
 */
ssize_t
gotr_symmetric_decrypt (const void *block, size_t size,
                                 const struct gotr_SymmetricSessionKey *sessionkey,
                                 const struct gotr_SymmetricInitializationVector *iv,
                                 void *result)
{
  gcry_cipher_hd_t handle;
  char tmp[size];

  if (/*GNUNET_OK*/ 1 != setup_cipher_twofish (&handle, sessionkey, iv))
    return -1;
  /*GNUNET_assert (0 == */gcry_cipher_decrypt (handle, tmp, size, block, size);//);
  gcry_cipher_close (handle);
  if (/*GNUNET_OK*/ 1 != setup_cipher_aes (&handle, sessionkey, iv))
    return -1;
  /*GNUNET_assert (0 == */gcry_cipher_decrypt (handle, result, size, tmp, size);//);
  gcry_cipher_close (handle);
  memset (tmp, 0, sizeof (tmp));
  return size;
}


/**
 * @brief Derive an IV
 *
 * @param iv initialization vector
 * @param skey session key
 * @param salt salt for the derivation
 * @param salt_len size of the @a salt
 * @param ... pairs of void * & size_t for context chunks, terminated by NULL
 */
void
gotr_symmetric_derive_iv (struct gotr_SymmetricInitializationVector *iv,
                             const struct gotr_SymmetricSessionKey *skey,
                             const void *salt, size_t salt_len, ...)
{
  va_list argp;

  va_start (argp, salt_len);
  gotr_symmetric_derive_iv_v (iv, skey, salt, salt_len, argp);
  va_end (argp);
}


/**
 * @brief Derive an IV
 *
 * @param iv initialization vector
 * @param skey session key
 * @param salt salt for the derivation
 * @param salt_len size of the salt
 * @param argp pairs of void * & size_t for context chunks, terminated by NULL
 */
void
gotr_symmetric_derive_iv_v (struct gotr_SymmetricInitializationVector *iv,
                               const struct gotr_SymmetricSessionKey *skey,
                               const void *salt, size_t salt_len, va_list argp)
{
  char aes_salt[salt_len + 4];
  char twofish_salt[salt_len + 4];

  memcpy (aes_salt, salt, salt_len);
  memcpy (&aes_salt[salt_len], "AES!", 4);
  memcpy (twofish_salt, salt, salt_len);
  memcpy (&twofish_salt[salt_len], "FISH", 4);
  gotr_kdf_v (iv->aes_iv, sizeof (iv->aes_iv),
                       aes_salt, salt_len + 4,
                       skey->aes_key, sizeof (skey->aes_key),
                       argp);
  gotr_kdf_v (iv->twofish_iv, sizeof (iv->twofish_iv),
                       twofish_salt, salt_len + 4,
                       skey->twofish_key, sizeof (skey->twofish_key),
                       argp);
}



// --- KDF ---

/**
 * @brief Derive key
 * @param result buffer for the derived key, allocated by caller
 * @param out_len desired length of the derived key
 * @param xts salt
 * @param xts_len length of @a xts
 * @param skm source key material
 * @param skm_len length of @a skm
 * @param argp va_list of void * & size_t pairs for context chunks
 * @return #GNUNET_YES on success
 */
int
gotr_kdf_v (void *result, size_t out_len, const void *xts,
                     size_t xts_len, const void *skm, size_t skm_len,
                     va_list argp)
{
  /*
   * "Finally, we point out to a particularly advantageous instantiation using
   * HMAC-SHA512 as XTR and HMAC-SHA256 in PRF* (in which case the output from SHA-512 is
   * truncated to 256 bits). This makes sense in two ways: First, the extraction part is where we need a
   * stronger hash function due to the unconventional demand from the hash function in the extraction
   * setting. Second, as shown in Section 6, using HMAC with a truncated output as an extractor
   * allows to prove the security of HKDF under considerably weaker assumptions on the underlying
   * hash function."
   *
   * http://eprint.iacr.org/2010/264
   */

  return gotr_hkdf_v (result, out_len, GCRY_MD_SHA512, GCRY_MD_SHA256,
                               xts, xts_len, skm, skm_len, argp);
}

/**
 * @brief Compute the HMAC
 * @todo use chunked buffers
 * @param mac gcrypt MAC handle
 * @param key HMAC key
 * @param key_len length of key
 * @param buf message to be processed
 * @param buf_len length of buf
 * @return HMAC, freed by caller via gcry_md_close/_reset
 */
static const void *
doHMAC (gcry_md_hd_t mac, const void *key, size_t key_len, const void *buf,
        size_t buf_len)
{
  gcry_md_setkey (mac, key, key_len);
  gcry_md_write (mac, buf, buf_len);

  return (const void *) gcry_md_read (mac, 0);
}

/**
 * @brief Generate pseudo-random key
 * @param mac gcrypt HMAC handle
 * @param xts salt
 * @param xts_len length of the @a xts salt
 * @param skm source key material
 * @param skm_len length of @a skm
 * @param prk result buffer (allocated by caller; at least gcry_md_dlen() bytes)
 * @return #GNUNET_YES on success
 */
static int
getPRK (gcry_md_hd_t mac, const void *xts, size_t xts_len, const void *skm,
        size_t skm_len, void *prk)
{
  const void *ret;

  ret = doHMAC (mac, xts, xts_len, skm, skm_len);
  if (ret == NULL) {
  	//return GNUNET_SYSERR;
	return -1;
	
  }
    
  memcpy (prk, ret, gcry_md_get_algo_dlen (gcry_md_get_algo (mac)));

  //return GNUNET_YES;
  return 1;
}

/**
 * @brief Derive key
 * @param result buffer for the derived key, allocated by caller
 * @param out_len desired length of the derived key
 * @param xtr_algo hash algorithm for the extraction phase, GCRY_MD_...
 * @param prf_algo hash algorithm for the expansion phase, GCRY_MD_...
 * @param xts salt
 * @param xts_len length of @a xts
 * @param skm source key material
 * @param skm_len length of @a skm
 * @param argp va_list of void * & size_t pairs for context chunks
 * @return #GNUNET_YES on success
 */
int
gotr_hkdf_v (void *result, size_t out_len, int xtr_algo, int prf_algo,
                      const void *xts, size_t xts_len, const void *skm,
                      size_t skm_len, va_list argp)
{
  gcry_md_hd_t xtr;
  gcry_md_hd_t prf;
  const void *hc;
  unsigned long i;
  unsigned long t;
  unsigned long d;
  unsigned int k = gcry_md_get_algo_dlen (prf_algo);
  unsigned int xtr_len = gcry_md_get_algo_dlen (xtr_algo);
  char prk[xtr_len];
  int ret;
  size_t ctx_len;
  va_list args;

  if (0 == k) {
  	//return GNUNET_SYSERR;
	return -1;
  }
    
  if (GPG_ERR_NO_ERROR !=
      gcry_md_open (&xtr, xtr_algo, GCRY_MD_FLAG_HMAC)) {
      	//return GNUNET_SYSERR;
		return -1;
      }
    
  if (GPG_ERR_NO_ERROR !=
      gcry_md_open (&prf, prf_algo, GCRY_MD_FLAG_HMAC))
  {
    gcry_md_close (xtr);
    //return GNUNET_SYSERR;
	return -1;
  }
  va_copy (args, argp);

  ctx_len = 0;
  while (NULL != va_arg (args, void *))
         ctx_len += va_arg (args, size_t);

  va_end (args);

  memset (result, 0, out_len);
  if (getPRK (xtr, xts, xts_len, skm, skm_len, prk) != 1 /*GNUNET_YES*/)
    goto hkdf_error;
#if DEBUG_HKDF
  dump ("PRK", prk, xtr_len);
#endif

  t = out_len / k;
  d = out_len % k;

  /* K(1) */
  {
    size_t plain_len = k + ctx_len + 1;
    char plain[plain_len];
    const void *ctx;
    char *dst;

    dst = plain + k;
    va_copy (args, argp);
    while ((ctx = va_arg (args, void *)))
    {
      size_t len;

      len = va_arg (args, size_t);
      memcpy (dst, ctx, len);
      dst += len;
    }
    va_end (args);

    if (t > 0)
    {
      memset (plain + k + ctx_len, 1, 1);
#if DEBUG_HKDF
      dump ("K(1)", plain, plain_len);
#endif
      hc = doHMAC (prf, prk, xtr_len, &plain[k], ctx_len + 1);
      if (hc == NULL)
        goto hkdf_error;
      memcpy (result, hc, k);
      result += k;
    }

    /* K(i+1) */
    for (i = 1; i < t; i++)
    {
      memcpy (plain, result - k, k);
      memset (plain + k + ctx_len, i + 1, 1);
      gcry_md_reset (prf);
#if DEBUG_HKDF
      dump ("K(i+1)", plain, plain_len);
#endif
      hc = doHMAC (prf, prk, xtr_len, plain, plain_len);
      if (hc == NULL)
        goto hkdf_error;
      memcpy (result, hc, k);
      result += k;
    }

    /* K(t):d */
    if (d > 0)
    {
      if (t > 0)
      {
        memcpy (plain, result - k, k);
        i++;
      }
      memset (plain + k + ctx_len, i, 1);
      gcry_md_reset (prf);
#if DEBUG_HKDF
      dump ("K(t):d", plain, plain_len);
#endif
      if (t > 0)
        hc = doHMAC (prf, prk, xtr_len, plain, plain_len);
      else
        hc = doHMAC (prf, prk, xtr_len, plain + k, plain_len - k);
      if (hc == NULL)
        goto hkdf_error;
      memcpy (result, hc, d);
    }
#if DEBUG_HKDF
    dump ("result", result - k, out_len);
#endif

    //ret = GNUNET_YES;
	ret = 1;
    goto hkdf_ok;
  }
hkdf_error:
  //ret = GNUNET_SYSERR;
  ret = -1;
hkdf_ok:
  gcry_md_close (xtr);
  gcry_md_close (prf);
  return ret;
}
