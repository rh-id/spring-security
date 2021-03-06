/*
 * Copyright 2015-2020 the original author or authors.
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

package org.springframework.security.web.jackson2;

import java.io.IOException;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.json.JSONException;
import org.junit.Test;
import org.skyscreamer.jsonassert.JSONAssert;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.web.csrf.DefaultCsrfToken;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Jitendra Singh
 * @since 4.2
 */
public class DefaultCsrfTokenMixinTests extends AbstractMixinTests {

	// @formatter:off
	public static final String CSRF_JSON = "{"
		+ "\"@class\": \"org.springframework.security.web.csrf.DefaultCsrfToken\", "
		+ "\"headerName\": \"csrf-header\", "
		+ "\"parameterName\": \"_csrf\", "
		+ "\"token\": \"1\""
	+ "}";
	// @formatter:on

	@Override
	public void setup() {
		mapper = new ObjectMapper();
		ClassLoader loader = getClass().getClassLoader();
		mapper.registerModules(SecurityJackson2Modules.getModules(loader));
		mapper.setVisibility(mapper.getSerializationConfig().getDefaultVisibilityChecker()
				.withFieldVisibility(JsonAutoDetect.Visibility.ANY)
				.withGetterVisibility(JsonAutoDetect.Visibility.NONE));
	}

	@Test
	public void defaultCsrfTokenSerializedTest() throws JsonProcessingException, JSONException {
		DefaultCsrfToken token = new DefaultCsrfToken("csrf-header", "_csrf", "1");
		String serializedJson = mapper.writeValueAsString(token);
		JSONAssert.assertEquals(CSRF_JSON, serializedJson, true);
	}

	@Test
	public void defaultCsrfTokenDeserializeTest() throws IOException {
		DefaultCsrfToken token = mapper.readValue(CSRF_JSON, DefaultCsrfToken.class);
		DefaultCsrfToken defaultCsrfToken = new DefaultCsrfToken("csrf-header", "_csrf", "1");
		assertThat(token).isNotNull();
		assertThat(token.getHeaderName()).isEqualTo("csrf-header");
		assertThat(token.getParameterName()).isEqualTo("_csrf");
		assertThat(token.matches(defaultCsrfToken.getToken())).isTrue();
	}

	@Test(expected = JsonMappingException.class)
	public void defaultCsrfTokenDeserializeWithoutClassTest() throws IOException {
		String tokenJson = "{\"headerName\": \"csrf-header\", \"parameterName\": \"_csrf\", \"token\": \"1\"}";
		mapper.readValue(tokenJson, DefaultCsrfToken.class);
	}

	@Test(expected = JsonMappingException.class)
	public void defaultCsrfTokenDeserializeNullValuesTest() throws IOException {
		String tokenJson = "{\"@class\": \"org.springframework.security.web.csrf.DefaultCsrfToken\", \"headerName\": \"\", \"parameterName\": null, \"token\": \"1\"}";
		mapper.readValue(tokenJson, DefaultCsrfToken.class);
	}
}
