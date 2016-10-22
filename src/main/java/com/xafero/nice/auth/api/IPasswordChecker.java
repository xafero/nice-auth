package com.xafero.nice.auth.api;

/**
 * For checking passwords
 */
public interface IPasswordChecker {

    CheckResult checkPassword(String password);

    /**
     * The result of the check
     */
    public enum CheckResult {
        OK,
        TooShort,
        DontSpace,
        FewLetters,
        FewSymbols,
        FewDigits
    }
}
