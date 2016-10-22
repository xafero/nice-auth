package com.xafero.nice.auth.impl;

import com.xafero.nice.auth.api.Algorithm;
import com.xafero.nice.auth.api.IPasswordHash;

public class PasswordHash implements IPasswordHash {

    private final Algorithm algorithm;
    private final int iterations;
    private final int hashSize;
    private final String salt;
    private final String hash;

    public PasswordHash(String text) {
        String[] tmp = text.split(":");
        algorithm = Algorithm.valueOf(tmp[0]);
        iterations = Integer.parseInt(tmp[1]);
        hashSize = Integer.parseInt(tmp[2]);
        salt = tmp[3];
        hash = tmp[4];
    }

    public PasswordHash(Algorithm algorithm, int iterations,
            int hashSize, String salt, String hash) {
        this.algorithm = algorithm;
        this.iterations = iterations;
        this.hashSize = hashSize;
        this.salt = salt;
        this.hash = hash;
    }

    @Override
    public Algorithm getAlgorithm() {
        return algorithm;
    }

    @Override
    public int getIterations() {
        return iterations;
    }

    @Override
    public int getHashSize() {
        return hashSize;
    }

    @Override
    public String getSalt() {
        return salt;
    }

    @Override
    public String getHash() {
        return hash;
    }

    @Override
    public String toString() {
        return String.format("%s:%s:%s:%s:%s",
                algorithm, iterations, hashSize, salt, hash);
    }
}
