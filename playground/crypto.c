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
GOTR_hash (const void *block,
                    size_t size,
                    struct GOTR_HashCode *ret)
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
GOTR_mpi_print_unsigned (void *buf,
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
decode_private_eddsa_key (const struct GOTR_EddsaPrivateKey *priv)
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
GOTR_eddsa_key_get_public (const struct GOTR_EddsaPrivateKey *priv,
                                    struct GOTR_EddsaPublicKey *pub)
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
  GOTR_mpi_print_unsigned (pub->q_y, sizeof (pub->q_y), q);
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
GOTR_eddsa_key_clear (struct GOTR_EddsaPrivateKey *pk)
{
  memset (pk, 0, sizeof (struct GOTR_EddsaPrivateKey));
}

/**
 * Create a new private key. Caller must free return value.
 *
 * @return fresh private key
 */
struct GOTR_EddsaPrivateKey *
GOTR_eddsa_key_create ()
{
  struct GOTR_EddsaPrivateKey *priv;
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
  priv = malloc(sizeof(struct GOTR_EddsaPrivateKey));
  GOTR_mpi_print_unsigned (priv->d, sizeof (priv->d), d);
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
data_to_eddsa_value (const struct GOTR_EccSignaturePurpose *purpose)
{
  struct GOTR_HashCode hc;
  gcry_sexp_t data;
  int rc;

  GOTR_hash (purpose, ntohl (purpose->size), &hc);
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
GOTR_eddsa_sign (const struct GOTR_EddsaPrivateKey *priv,
                          const struct GOTR_EccSignaturePurpose *purpose,
                          struct GOTR_EddsaSignature *sig)
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
  GOTR_mpi_print_unsigned (sig->r, sizeof (sig->r), rs[0]);
  GOTR_mpi_print_unsigned (sig->s, sizeof (sig->s), rs[1]);
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
GOTR_eddsa_verify (uint32_t purpose,
                            const struct GOTR_EccSignaturePurpose *validate,
                            const struct GOTR_EddsaSignature *sig,
                            const struct GOTR_EddsaPublicKey *pub)
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