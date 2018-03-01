/*
 * TokenFilter.java
 * Version: 1.0
 * Copyright 2018 Thomas Schwade
 * http://www.zerodrive.net
 * Licensed under the EUPL V.1.1
 * https://github.com/zerodrive/NJX-SSOServices/blob/master/LICENSE.pdf
 */

package net.zerodrive.ssoservices;

import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

/*
 * This servlet filter takes a servlet request containing "...&token=<token>",
 * checks if the token is a valid authentication token and (if so) transforms the
 * request to "...&xciParameters.natuser=<user>&xciParameters.natpassword=<password>".
 */
public class TokenFilter implements Filter {

    @Override
    public void destroy() {
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain)
            throws IOException, ServletException {
        HttpServletRequestWrapper requestMod = new HttpServletRequestWrapper((HttpServletRequest) request) {

            private final long tokenLifetime = 2000;
            private final String tokenPattern = "(.*) (\\d{13}) (.*)";
            private final String userParm = "xciParameters.natuser";
            private final String pwdParm = "xciParameters.natpassword";
            private final String tokenParm = "token";

            /*
             * If userID or password are requested, we check if the parameter
             * "token" is specified and try to extract userID and password from
             * the token.
             */
            @Override
            public String getParameter(String parm) {
                String userName = null;
                String tokenTimeMillis = null;
                String password = null;

                if (parm.equals(userParm) || parm.equals(pwdParm)) {
                    String tokenEncrypted = this.getParameter(tokenParm);
                    if (tokenEncrypted == null || tokenEncrypted.isEmpty()) {
                        return super.getParameter(parm);
                    }

                    Encryption crypt = new Encryption();
                    String tokenDecrypted;
                    try {
                        tokenDecrypted = crypt.decrypt(tokenEncrypted);
                    } catch (Exception e) {
                        return super.getParameter(parm);
                    }

                    /*
                     * As a safeguard against misuse of the token we accept the
                     * token only if it is not older than two seconds.
                     */
                    Pattern p = Pattern.compile(tokenPattern);
                    Matcher m = p.matcher(tokenDecrypted);
                    if (m.find()) {
                        userName = m.group(1);
                        tokenTimeMillis = m.group(2);
                        password = m.group(3);
                        if (System.currentTimeMillis() - Long.parseLong(tokenTimeMillis) > tokenLifetime) {
                            return super.getParameter(parm);
                        }
                    } else {
                        return super.getParameter(parm);
                    }
                }

                if (parm.equals(userParm)) {
                    return userName;
                } else if (parm.equals(pwdParm)) {
                    return password;
                } else {
                    return super.getParameter(parm);
                }
            }

            @Override
            public String getQueryString() {
                String userName = null;
                String tokenTimeMillis = null;
                String password = null;
                String queryDecrypted = null;

                String query = super.getQueryString();

                /*
                 * As a safeguard against misuse of the token we accept a token
                 * only if the query originates from our own IP address.
                 */
                String remoteAddr = super.getRemoteAddr();
                String localAddr = super.getLocalAddr();
                if (!remoteAddr.equalsIgnoreCase(localAddr)) {
                    return query;
                }

                String tokenEncrypted = super.getParameter(tokenParm);
                if (tokenEncrypted == null) {
                    return query;
                }

                Encryption crypt = new Encryption();
                String tokenDecrypted;
                try {
                    tokenDecrypted = crypt.decrypt(tokenEncrypted);
                } catch (Exception e) {
                    queryDecrypted = query.replaceFirst("&" + tokenParm + '=' + tokenEncrypted, "");
                    return queryDecrypted;
                }

                /*
                 * As a safeguard against misuse of the token we accept the
                 * token only if it is not older than two seconds.
                 */
                Pattern p = Pattern.compile(tokenPattern);
                Matcher m = p.matcher(tokenDecrypted);
                if (m.find()) {
                    userName = m.group(1);
                    tokenTimeMillis = m.group(2);
                    password = m.group(3);
                    if (System.currentTimeMillis() - Long.parseLong(tokenTimeMillis) > tokenLifetime) {
                        queryDecrypted = query.replaceFirst("&" + tokenParm + '=' + tokenEncrypted, "");
                        return queryDecrypted;
                    } else {
                        queryDecrypted = query.replaceFirst("&" + tokenParm + '=' + tokenEncrypted,
                                "&" + userParm + '=' + userName + "&" + pwdParm + '=' + password);
                        return queryDecrypted;
                    }
                } else {
                    queryDecrypted = query.replaceFirst("&" + tokenParm + '=' + tokenEncrypted, "");
                    return queryDecrypted;
                }
            }
        };

        filterChain.doFilter(requestMod, response);
    }

    @Override
    public void init(FilterConfig arg0) throws ServletException {
    }

}
