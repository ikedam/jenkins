/*
 * The MIT License
 * 
 * Copyright (c) 2016 IKEDA Yasuyuki
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package jenkins.security;

import hudson.util.Secret;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.Cipher;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

import org.apache.commons.codec.binary.Base64;

import jenkins.model.Jenkins;
import net.sf.json.JSONArray;
import net.sf.json.JSONException;
import net.sf.json.JSONObject;

/**
 * Decrypts form values encrypted with JavaScript.
 * This doesn't work with multipart request body.
 * 
 * @since TODO
 */
public class DecryptFieldFilter implements Filter {
    private static final Logger LOGGER = Logger.getLogger(DecryptFieldFilter.class.getName());
    private static final String ENCRYPT_PREFIX = "{ENCRYPTED}";
    /**
     * {@inheritDoc}
     */
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
    }
    
    /**
     * {@inheritDoc}
     */
    @Override
    public void destroy() {
    }
    
    /**
     * {@inheritDoc}
     */
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException
    {
        if (request instanceof HttpServletRequest) {
            chain.doFilter(new ServletRequestImpl((HttpServletRequest)request), response);
        } else {
            chain.doFilter(request, response);
        }
    }
    
    private static class ServletRequestImpl extends HttpServletRequestWrapper {
        public ServletRequestImpl(HttpServletRequest request) {
            super(request);
        }
        
        @Override
        public String getParameter(String name) {
            if ("json".equals(name)) {
                return decryptJson(super.getParameter("json"));
            }
            return super.getParameter(name);
        }
        
        private String decryptJson(String jsonString) {
            if (jsonString == null) {
                return jsonString;
            }
            JSONObject json = null;
            try {
                json = JSONObject.fromObject(jsonString);
            } catch (JSONException e) {
                return jsonString;
            }
            JSONObject decrypt = scanAndDecrypt(json);
            return decrypt.toString();
        }
        
        private <T> T scanAndDecrypt(T jsonElement) {
            if (jsonElement == null) {
                return jsonElement;
            } else if (jsonElement instanceof JSONObject) {
                JSONObject json = (JSONObject)jsonElement;
                if (json.isNullObject()) {
                    return jsonElement;
                }
                for (Object key: json.keySet()) {
                    if (key instanceof String) {
                        json.put(
                                (String)key,
                                scanAndDecrypt(json.get(key))
                        );
                    }
                }
            } else if (jsonElement instanceof JSONArray) {
                JSONArray ary = (JSONArray)jsonElement;
                for (int i = 0; i < ary.size(); ++i) {
                    ary.set(i, scanAndDecrypt(ary.get(i)));
                }
            } else if (jsonElement instanceof String) {
                String value = (String)jsonElement;
                if (!value.startsWith(ENCRYPT_PREFIX)) {
                    return jsonElement;
                }
                String encrypted = value.substring(ENCRYPT_PREFIX.length());
                
                Cipher dec;
                try {
                    dec = Secret.getCipher("RSA");
                    dec.init(
                            Cipher.DECRYPT_MODE,
                            Jenkins.getInstance().getTransientKey().getPrivateKey()
                    );
                    byte[] decoded = dec.doFinal(Base64.decodeBase64(encrypted));
                    
                    @SuppressWarnings("unchecked")
                    T decodedValue = (T)(new String(decoded, "UTF-8"));
                    return decodedValue;
                } catch (GeneralSecurityException e) {
                    LOGGER.log(Level.SEVERE, "Failed to decrypt form value", e);
                } catch (UnsupportedEncodingException e) {
                    LOGGER.log(Level.SEVERE, "Failed to decrypt form value", e);
                }
                
            }
            
            return jsonElement;
        }
    }
}
