/*
 * GetToken.java
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

public class GetToken implements IAdapterListener {

	private final String tokenKey = "net.zerodrive.ssoservices.token";
	private final String tokenDatafield = "token";
	private final String getTokenEvent = "onGetToken";
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
	 * When the user fires the <getTokenEvent> event on this page, read the
	 * encrypted userID and password from the session context, create an
	 * authentication token with a limited lifetime and return this token in the
	 * data field <tokenDatafield> on the page.
	 */
	@Override
	public void reactOnInvokePhaseStart() {
		if (m_adapter instanceof IDynamicAccess) {
			String event = m_adapter.findCurrentlyProcessedMethod();
			String token;
			if (event != null && event.equals(getTokenEvent)) {
				ILookupContext ctx = m_adapter.findSessionContext();
				token = (String) ctx.lookup(tokenKey, false);
				try {
					Encryption crypt = new Encryption();
					String tokenDec = crypt.decrypt(token);
					String[] namepass = tokenDec.split(" ");
					token = crypt.encrypt(namepass[0] + " " + System.currentTimeMillis() + " " + namepass[1]);
					namepass = null;
					((IDynamicAccess) m_adapter).setPropertyValue(tokenDatafield, token);

        } catch (EncryptionException e) {
          System.out.println("Temporary authentication token could not be created." + e.toString());
				}
			}
		}
	}

}
