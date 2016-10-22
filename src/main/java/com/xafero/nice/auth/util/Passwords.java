package com.xafero.nice.auth.util;

import com.xafero.nice.auth.api.IPasswordChecker;

public class Passwords {

    private Passwords() {
    }

    public static final IPasswordChecker LightCheck = new IPasswordChecker() {
        @Override
        public CheckResult checkPassword(String password) {
            return password.trim().length() >= 8 ? CheckResult.OK
                    : CheckResult.TooShort;
        }
    };

    public static final IPasswordChecker SpecialCheck = new IPasswordChecker() {
        @Override
        public CheckResult checkPassword(String password) {
            if (password.trim().length() < 12) {
                return CheckResult.TooShort;
            }
            int letters = 0;
            int digits = 0;
            int spaces = 0;
            int symbols = 0;
            for (char sign : password.toCharArray()) {
                if (Character.isLetter(sign)) {
                    letters++;
                } else if (Character.isDigit(sign)) {
                    digits++;
                } else if (Character.isWhitespace(sign)) {
                    spaces++;
                } else {
                    symbols++;
                }
            }
            if (spaces > 0) {
                return CheckResult.DontSpace;
            }
            if (letters < 2) {
                return CheckResult.FewLetters;
            }
            if (digits < 2) {
                return CheckResult.FewDigits;
            }
            if (symbols < 2) {
                return CheckResult.FewSymbols;
            }
            return CheckResult.OK;
        }
    };
}
