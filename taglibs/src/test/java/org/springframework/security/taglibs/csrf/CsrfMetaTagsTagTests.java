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
package org.springframework.security.taglibs.csrf;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.DefaultCsrfToken;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import static org.assertj.core.api.Assertions.*;

import java.io.ByteArrayInputStream;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;

/**
 * @author Nick Williams
 * @author Ruby Hartono
 */
public class CsrfMetaTagsTagTests {

	public CsrfMetaTagsTag tag;

	private XPath xPath;

	@Before
	public void setUp() {
		this.tag = new CsrfMetaTagsTag();
		this.xPath = XPathFactory.newInstance().newXPath();
	}

	@Test
	public void handleTokenRendersTags() throws Exception {
		CsrfToken token = new DefaultCsrfToken("X-Csrf-Token", "_csrf", "abc123def456ghi789");

		String value = this.tag.handleToken(token);

		assertThat(value).as("The returned value should not be null.").isNotNull();

		String expression = "//meta";
		NodeList node = (NodeList) xPath.compile(expression).evaluate(getDocument(value), XPathConstants.NODESET);
		String metaName = node.item(0).getAttributes().getNamedItem("name").getNodeValue();
		String metaContent = node.item(0).getAttributes().getNamedItem("content").getNodeValue();

		assertThat(metaName).isEqualTo("_csrf_parameter");
		assertThat(metaContent).isEqualTo("_csrf");

		metaName = node.item(1).getAttributes().getNamedItem("name").getNodeValue();
		metaContent = node.item(1).getAttributes().getNamedItem("content").getNodeValue();

		assertThat(metaName).isEqualTo("_csrf_header");
		assertThat(metaContent).isEqualTo("X-Csrf-Token");

		metaName = node.item(2).getAttributes().getNamedItem("name").getNodeValue();
		metaContent = node.item(2).getAttributes().getNamedItem("content").getNodeValue();

		assertThat(metaName).isEqualTo("_csrf");
		assertThat(token.matches(metaContent)).isTrue();
	}

	@Test
	public void handleTokenRendersTagsDifferentToken() throws Exception {
		CsrfToken token = new DefaultCsrfToken("csrfHeader", "csrfParameter", "fooBarBazQux");

		String value = this.tag.handleToken(token);

		assertThat(value).as("The returned value should not be null.").isNotNull();

		String expression = "//meta";
		NodeList node = (NodeList) xPath.compile(expression).evaluate(getDocument(value), XPathConstants.NODESET);
		String metaName = node.item(0).getAttributes().getNamedItem("name").getNodeValue();
		String metaContent = node.item(0).getAttributes().getNamedItem("content").getNodeValue();

		assertThat(metaName).isEqualTo("_csrf_parameter");
		assertThat(metaContent).isEqualTo("csrfParameter");

		metaName = node.item(1).getAttributes().getNamedItem("name").getNodeValue();
		metaContent = node.item(1).getAttributes().getNamedItem("content").getNodeValue();

		assertThat(metaName).isEqualTo("_csrf_header");
		assertThat(metaContent).isEqualTo("csrfHeader");

		metaName = node.item(2).getAttributes().getNamedItem("name").getNodeValue();
		metaContent = node.item(2).getAttributes().getNamedItem("content").getNodeValue();

		assertThat(metaName).isEqualTo("_csrf");
		assertThat(token.matches(metaContent)).isTrue();
	}

	private static Document getDocument(String value) throws Exception {
		String xmlVersion = "<?xml version=\"1.0\" encoding=\"utf-8\" ?>";
		value = xmlVersion + "<testResult>" + value + "</testResult>";
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		DocumentBuilder builder = factory.newDocumentBuilder();
		Document doc = builder.parse(new ByteArrayInputStream(value.getBytes()));
		return doc;
	}
}
