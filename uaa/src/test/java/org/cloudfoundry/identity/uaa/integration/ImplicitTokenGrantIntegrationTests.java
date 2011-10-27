package org.cloudfoundry.identity.uaa.integration;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.net.URI;
import java.util.Arrays;

import org.junit.Rule;
import org.junit.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

/**
 * Tests implicit grant using a direct posting of credentials to the /authorize endpoint and
 * also with an intermediate form login.
 * 
 * @author Dave Syer
 */
public class ImplicitTokenGrantIntegrationTests {

	@Rule
	public ServerRunning serverRunning = ServerRunning.isRunning();

	private String implicitUrl() {
		URI uri = serverRunning.buildUri("/cloudfoundry-identity-uaa/oauth/authorize").queryParam("response_type", "token")
				.queryParam("client_id", "vmc").queryParam("redirect_uri", "http://anywhere")
				.queryParam("scope", "read_vcap").build();
		return uri.toString();
	}

	@Test
	public void authzViaJsonEndpointSucceedsWithCorrectCredentials() throws Exception {
		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));

		String credentials = "{ \"username\":\"marissa\", \"password\":\"koala\" }";
//	Use GET for now, because of Spring MVC issues...
//		MultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
//		formData.add("credentials", credentials);

		String url = implicitUrl() + "&credentials={creds}";

		System.out.println(url);
		ResponseEntity<Void> result = serverRunning.getForResponse(url, headers, credentials);
		assertNotNull(result.getHeaders().getLocation());
		assertTrue(result.getHeaders().getLocation().toString().matches("http://anywhere#access_token=.+"));
	}

	@Test
	public void authzWithIntermediateFormLoginSucceeds() throws Exception {

		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Arrays.asList(MediaType.TEXT_HTML));

		ResponseEntity<Void> result = serverRunning.getForResponse(implicitUrl(), headers);
		assertEquals(HttpStatus.FOUND, result.getStatusCode());
		String location = result.getHeaders().getLocation().toString();
		String cookie = result.getHeaders().getFirst("Set-Cookie");

		assertNotNull("Expected cookie in " + result.getHeaders(), cookie);
		headers.set("Cookie", cookie);

		ResponseEntity<String> response = serverRunning.getForString(location, headers);
		// should be directed to the login screen...
		assertTrue(response.getBody().contains("uaa/login.do"));
		assertTrue(response.getBody().contains("username"));
		assertTrue(response.getBody().contains("password"));

		location = "cloudfoundry-identity-uaa/login.do";

		MultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
		formData.add("username", "marissa");
		formData.add("password", "koala");

		result = serverRunning.postForRedirect(location, headers, formData);

		System.err.println(result.getStatusCode());
		System.err.println(result.getHeaders());

		assertNotNull(result.getHeaders().getLocation());
		assertTrue(result.getHeaders().getLocation().toString().matches("http://anywhere#access_token=.+"));
	}

}