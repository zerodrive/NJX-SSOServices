/*
 * EncryptionException.java
 * Version: 1.0
 * Copyright 2018 Thomas Schwade
 * http://www.zerodrive.net
 * Licensed under the EUPL V.1.1
 * https://github.com/zerodrive/NJX-SSOServices/blob/master/LICENSE.pdf
 */

package net.zerodrive.ssoservices;

public class EncryptionException extends Exception {

    private static final long serialVersionUID = 2106102696353110983L;

    public EncryptionException(String message) {
        super(message);
    }

    public EncryptionException(String message, Throwable cause) {
        super(message, cause);
    }

}
