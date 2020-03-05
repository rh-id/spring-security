/*
 * Copyright 2002-2020 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.web.csrf;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Random;

import org.springframework.security.crypto.codec.Utf8;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * A CSRF token that is used to protect against CSRF attacks.
 *
 * @author Rob Winch
 * @author Ruby Hartono
 * @since 3.2
 */
@SuppressWarnings("serial")
public final class DefaultCsrfToken implements CsrfToken {

	private final String token;

	private final String parameterName;

	private final String headerName;

	/**
	 * Creates a new instance
	 * @param headerName the HTTP header name to use
	 * @param parameterName the HTTP parameter name to use
	 * @param token the value of the token (i.e. expected value of the HTTP parameter of
	 * parametername).
	 */
	public DefaultCsrfToken(String headerName, String parameterName, String token) {
		Assert.hasLength(headerName, "headerName cannot be null or empty");
		Assert.hasLength(parameterName, "parameterName cannot be null or empty");
		Assert.hasLength(token, "token cannot be null or empty");
		this.headerName = headerName;
		this.parameterName = parameterName;
		this.token = token;
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see org.springframework.security.web.csrf.CsrfToken#getHeaderName()
	 */
	public String getHeaderName() {
		return this.headerName;
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see org.springframework.security.web.csrf.CsrfToken#getParameterName()
	 */
	public String getParameterName() {
		return this.parameterName;
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see org.springframework.security.web.csrf.CsrfToken#getToken()
	 */
	public String getToken() {
		Random randomSize = new Random();
		int randomByteSize = randomSize.nextInt(251) + 5; // generate between 5 to 255
		ByteBuffer byteBuffer = ByteBuffer.allocate(randomByteSize);
		SecureRandom secureRandom = new SecureRandom();
		secureRandom.ints(Byte.MIN_VALUE, Byte.MAX_VALUE).limit(randomByteSize).forEach((randInt) -> byteBuffer.put((byte) randInt));

		byte[] randomBytes = byteBuffer.array();

		byte[] xoredCsrf = xorCsrf(randomBytes, Utf8.encode(this.token));

		ByteBuffer combinedBuffer = ByteBuffer.allocate(randomByteSize + xoredCsrf.length);
		combinedBuffer.put(randomBytes);
		combinedBuffer.put(xoredCsrf);

		// returning randomBytes + XOR csrf token
		return Base64.getEncoder().encodeToString(combinedBuffer.array());
	}

	private static byte[] xorCsrf(byte[] randomBytes, byte[] csrfBytes) {
		byte[] xoredCsrf = new byte[csrfBytes.length];
		System.arraycopy(csrfBytes, 0, xoredCsrf, 0, csrfBytes.length);
		for (byte b : randomBytes) {
			for (int i = 0; i < xoredCsrf.length; i++) {
				xoredCsrf[i] ^= b;
			}
		}

		return xoredCsrf;
	}

	@Override
	public boolean matches(String token) {
		if (StringUtils.isEmpty(token)) {
			return false;
		}

		byte[] tokenBytes = Utf8.encode(this.token);
		int tokenSize = tokenBytes.length;
		byte[] paramToken = null;

		try {
			paramToken = Base64.getDecoder().decode(token);
		} catch (IllegalArgumentException ex) {
			return false;
		}
		if (paramToken.length == tokenSize) {
			return MessageDigest.isEqual(tokenBytes, paramToken);
		} else if (paramToken.length < tokenSize) {
			return false;
		}

		// extract token and random bytes
		int paramXorTokenOffset = paramToken.length - tokenSize;
		ByteBuffer paramXoredToken = ByteBuffer.allocate(tokenSize);
		ByteBuffer paramRandomBytes = ByteBuffer.allocate(paramXorTokenOffset);

		for (int i = 0; i < paramToken.length; i++) {
			if (i >= paramXorTokenOffset) {
				paramXoredToken.put(paramToken[i]);
			} else {
				paramRandomBytes.put(paramToken[i]);
			}
		}

		byte[] paramActualCsrfToken = xorCsrf(paramRandomBytes.array(), paramXoredToken.array());

		// comparing this token with the actual csrf token from param
		return MessageDigest.isEqual(tokenBytes, paramActualCsrfToken);
	}
}
