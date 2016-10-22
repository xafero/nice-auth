package com.xafero.nice.auth.impl;

import com.xafero.nice.auth.api.Algorithm;
import com.xafero.nice.auth.api.IPasswordHash;
import com.xafero.nice.auth.api.ISecureHasher;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.xml.bind.DatatypeConverter;

public class PBKDF2Hasher implements ISecureHasher {

    private int saltByteSize = 24;
    private int iterations = 64000;
    private int hashByteSize = 18;
    private Algorithm defaultAlgo = Algorithm.sha1;

    public PBKDF2Hasher saltByteSize(int saltByteSize) {
        this.saltByteSize = saltByteSize;
        return this;
    }

    public PBKDF2Hasher iterations(int iterations) {
        this.iterations = iterations;
        return this;
    }

    public PBKDF2Hasher hashByteSize(int hashByteSize) {
        this.hashByteSize = hashByteSize;
        return this;
    }

    public PBKDF2Hasher defaultAlgo(Algorithm defaultAlgo) {
        this.defaultAlgo = defaultAlgo;
        return this;
    }

    @Override
    public IPasswordHash createHash(String password) {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[saltByteSize];
        random.nextBytes(salt);
        byte[] hash = hashThat(password, defaultAlgo, salt, iterations, hashByteSize);
        int hashSize = hash.length;
        return new PasswordHash(defaultAlgo, iterations,
                hashSize, toBase64(salt), toBase64(hash));
    }

    private static String toBase64(byte[] array) {
        return DatatypeConverter.printBase64Binary(array);
    }

    private static byte[] fromBase64(String text) {
        return DatatypeConverter.parseBase64Binary(text);
    }

    private static byte[] hashThat(String password, Algorithm algorithm,
            byte[] salt, int iterations, int bytes) {
        try {
            char[] array = password.toCharArray();
            String algo = algorithm.name().toUpperCase();
            PBEKeySpec spec = new PBEKeySpec(array, salt, iterations, bytes * 8);
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmac" + algo);
            return skf.generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            Logger.getLogger(PBKDF2Hasher.class.getName()).log(Level.SEVERE, ex.getMessage());
            return null;
        }
    }

    @Override
    public boolean verifyPassword(String password, IPasswordHash hash) {
        Algorithm algo = hash.getAlgorithm();
        byte[] salt = fromBase64(hash.getSalt());
        int its = hash.getIterations();
        byte[] oldHash = fromBase64(hash.getHash());
        if (hash.getHashSize() != oldHash.length) {
            return false;
        }
        byte[] testHash = hashThat(password, algo, salt, its, oldHash.length);
        return slowEquals(oldHash, testHash);
    }

    private static boolean slowEquals(byte[] a, byte[] b) {
        int diff = a.length ^ b.length;
        for (int i = 0; i < a.length && i < b.length; i++) {
            diff |= a[i] ^ b[i];
        }
        return diff == 0;
    }
}
