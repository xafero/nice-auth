package com.xafero.nice.auth;

import com.xafero.nice.auth.api.Algorithm;
import com.xafero.nice.auth.api.IPasswordHash;
import com.xafero.nice.auth.api.ISecureHasher;
import com.xafero.nice.auth.impl.PBKDF2Hasher;
import com.xafero.nice.auth.impl.PasswordHash;
import static org.junit.Assert.*;
import org.junit.Test;

public class PasswordsTest {

    /* github.com/defuse/password-hashing, "foobar" */
    private String[] testpws = new String[]{
        "sha1:64000:18:B6oWbvtHvu8qCgoE75wxmvpidRnGzGFt:R1gkPOuVjqIoTulWP1TABS0H",
        "sha1:64000:18:/GO9XQOPexBFVzRjC9mcOkVEi7ZHQc0/:0mY83V5PvmkkHRR41R1iIhx/",
        "sha1:64000:18:rxGkJ9fMTNU7ezyWWqS7QBOeYKNUcVYL:tn+Zr/xo99LI+kSwLOUav72X",
        "sha1:64000:18:lFtd+Qf93yfMyP6chCxJP5nkOxri6Zbh:B0awZ9cDJCTdfxUVwVqO+Mb5"
    };

    @Test
    public void testPasswordParse() {
        ISecureHasher hash = new PBKDF2Hasher();
        IPasswordHash pass = new PasswordHash(testpws[0]);
        assertEquals(Algorithm.sha1, pass.getAlgorithm());
        assertEquals(64000, pass.getIterations());
        assertEquals(18, pass.getHashSize());
        assertEquals("B6oWbvtHvu8qCgoE75wxmvpidRnGzGFt", pass.getSalt());
        assertEquals("R1gkPOuVjqIoTulWP1TABS0H", pass.getHash());
        assertTrue(hash.verifyPassword("foobar", pass));
        assertFalse(hash.verifyPassword("foobal", pass));
        pass = new PasswordHash(testpws[1]);
        assertEquals(Algorithm.sha1, pass.getAlgorithm());
        assertEquals(64000, pass.getIterations());
        assertEquals(18, pass.getHashSize());
        assertEquals("/GO9XQOPexBFVzRjC9mcOkVEi7ZHQc0/", pass.getSalt());
        assertEquals("0mY83V5PvmkkHRR41R1iIhx/", pass.getHash());
        assertTrue(hash.verifyPassword("foobar", pass));
        assertFalse(hash.verifyPassword("koobar", pass));
        pass = new PasswordHash(testpws[2]);
        assertEquals(Algorithm.sha1, pass.getAlgorithm());
        assertEquals(64000, pass.getIterations());
        assertEquals(18, pass.getHashSize());
        assertEquals("rxGkJ9fMTNU7ezyWWqS7QBOeYKNUcVYL", pass.getSalt());
        assertEquals("tn+Zr/xo99LI+kSwLOUav72X", pass.getHash());
        assertTrue(hash.verifyPassword("foobar", pass));
        assertFalse(hash.verifyPassword("loobar", pass));
        pass = new PasswordHash(testpws[3]);
        assertEquals(Algorithm.sha1, pass.getAlgorithm());
        assertEquals(64000, pass.getIterations());
        assertEquals(18, pass.getHashSize());
        assertEquals("lFtd+Qf93yfMyP6chCxJP5nkOxri6Zbh", pass.getSalt());
        assertEquals("B0awZ9cDJCTdfxUVwVqO+Mb5", pass.getHash());
        assertTrue(hash.verifyPassword("foobar", pass));
        assertFalse(hash.verifyPassword("fosbal", pass));
    }

    @Test
    public void testPasswordCreate() {
        ISecureHasher hash = new PBKDF2Hasher();
        IPasswordHash pass = hash.createHash("foobar");
        assertEquals(Algorithm.sha1, pass.getAlgorithm());
        assertEquals(64000, pass.getIterations());
        assertEquals(18, pass.getHashSize());
        assertEquals(32, pass.getSalt().length());
        assertEquals(24, pass.getHash().length());
        assertTrue(hash.verifyPassword("foobar", pass));
        assertFalse(hash.verifyPassword("fosbal", pass));
    }
}
