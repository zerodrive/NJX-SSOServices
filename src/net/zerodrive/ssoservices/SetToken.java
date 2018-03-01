/*
 * SetToken.java
 * Version: 1.0
 * Copyright 2018 Thomas Schwade
 * http://www.zerodrive.net
 * Licensed under the EUPL V.1.1
 * https://github.com/zerodrive/NJX-SSOServices/blob/master/LICENSE.pdf
 */

package net.zerodrive.ssoservices;

import com.softwareag.cis.context.ILookupContext;
import com.softwareag.cis.server.Adapter;
import com.softwareag.cis.server.IAdapterListener;
import com.softwareag.cis.server.IDynamicAccess;

public class SetToken implements IAdapterListener {

    private final String tokenKey = "net.zerodrive.ssoservices.token";
    private final String userNameField = "userName";
    private final String passwordField = "password";
    private final String connectEvent = "onConnect";
    private Adapter m_adapter = null;

    @Override
    public void init(Adapter adapter) {
        m_adapter = adapter;
    }

    @Override
    public void reactOnDataCollectionEnd() {
    }

    @Override
    public void reactOnDataCollectionStart() {
    }

    @Override
    public void reactOnDataTransferEnd() {
    }

    @Override
    public void reactOnDataTransferStart() {
    }

    @Override
    public void reactOnDestroy() {
    }

    @Override
    public void reactOnInvokePhaseEnd() {
    }

    /*
     * When the user clicks the "Connect" button on the Logon page, encrypt
     * userID and password using the public key of a given key pair and store
     * the encrypted value in the session context.
     */
    @Override
    public void reactOnInvokePhaseStart() {
        if (m_adapter instanceof IDynamicAccess) {
            String event = m_adapter.findCurrentlyProcessedMethod();
            if (event != null && event.equals(connectEvent)) {
                ILookupContext ctx = m_adapter.findSessionContext();
                try {
                    Encryption crypt = new Encryption();
                    ctx.bind(tokenKey,
                            crypt.encrypt((String) ((IDynamicAccess) m_adapter).getPropertyValue(userNameField) + " "
                                    + (String) ((IDynamicAccess) m_adapter).getPropertyValue(passwordField)));
                } catch (EncryptionException e) {
                    System.out.println("Authentication token could not be created." + e.toString());
                }
            }
        }
    }

}
