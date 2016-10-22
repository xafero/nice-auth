package com.xafero.nice.auth.api;

/**
 * For securely storing and comparing passwords
 */
public interface ISecureHasher {

    /**
     * Creates a hash
     *
     * @param password for the new account or an existing account
     * @return a hash
     */
    IPasswordHash createHash(String password);

    /**
     * Verify a password
     *
     * @param password provided by the person trying to log in
     * @param hash the current correct password
     * @return true if the password is correct
     */
    boolean verifyPassword(String password, IPasswordHash hash);
}
