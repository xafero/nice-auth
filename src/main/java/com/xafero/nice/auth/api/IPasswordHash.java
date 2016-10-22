package com.xafero.nice.auth.api;

/**
 * For accessing one hash as an object-oriented unit
 */
public interface IPasswordHash {

    /**
     * The name of the cryptographic hash function
     *
     * @return
     */
    Algorithm getAlgorithm();

    /**
     * The number of hashing iterations
     *
     * @return
     */
    int getIterations();

    /**
     * The length, in bytes, of the hash field after decoding
     *
     * @return
     */
    int getHashSize();

    /**
     * The salt in base64 encoding
     *
     * @return
     */
    String getSalt();

    /**
     * The hashing output in base64 encoding
     *
     * @return
     */
    String getHash();
}
