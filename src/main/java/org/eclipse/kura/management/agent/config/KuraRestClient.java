package org.eclipse.kura.management.agent.config;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Base64;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Minimal client for the gateway-local Kura REST API (org.eclipse.kura.rest.configuration.provider,
 * base path /configuration/v2). Configuration via system properties:
 * kura.rest.baseUrl (default https://localhost), kura.rest.username / kura.rest.password (default admin/admin).
 */
public class KuraRestClient {

    public static class KuraRestException extends RuntimeException {

        private final int statusCode;

        public KuraRestException(int statusCode, String message) {
            super(message);
            this.statusCode = statusCode;
        }

        public int getStatusCode() {
            return this.statusCode;
        }
    }

    private final HttpClient httpClient;
    private final ObjectMapper mapper = new ObjectMapper();
    private final String baseUrl;
    private final String authorization;

    public KuraRestClient() {
        this.baseUrl = System.getProperty("kura.rest.baseUrl", "https://localhost");
        String username = System.getProperty("kura.rest.username", "admin");
        String password = System.getProperty("kura.rest.password", "admin");
        this.authorization = "Basic " + Base64.getEncoder()
                .encodeToString((username + ":" + password).getBytes(StandardCharsets.UTF_8));
        SSLParameters sslParameters = new SSLParameters();
        // leave endpoint identification unset: HttpClient would otherwise enforce
        // HTTPS hostname verification against the gateway's self-signed certificate
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .sslContext(trustAllContext())
                .sslParameters(sslParameters)
                .build();
    }

    public JsonNode get(String path) {
        return exchange("GET", path, null);
    }

    public JsonNode post(String path, Object body) {
        return exchange("POST", path, body);
    }

    public JsonNode put(String path, Object body) {
        return exchange("PUT", path, body);
    }

    private JsonNode exchange(String method, String path, Object body) {
        try {
            HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(this.baseUrl + path))
                    .timeout(Duration.ofSeconds(30))
                    .header("Authorization", this.authorization)
                    .header("Accept", "application/json");

            HttpRequest.BodyPublisher publisher = HttpRequest.BodyPublishers.noBody();
            if (body != null) {
                publisher = HttpRequest.BodyPublishers.ofString(this.mapper.writeValueAsString(body));
                builder.header("Content-Type", "application/json");
            }

            switch (method) {
                case "POST" -> builder.POST(publisher);
                case "PUT" -> builder.PUT(publisher);
                default -> builder.GET();
            }

            HttpResponse<String> response = this.httpClient.send(builder.build(), HttpResponse.BodyHandlers.ofString());
            String responseBody = response.body() == null ? "" : response.body();
            if (response.statusCode() >= 300) {
                throw new KuraRestException(response.statusCode(),
                        "Kura REST " + method + " " + path + " -> " + response.statusCode() + ": "
                                + truncate(responseBody));
            }
            if (responseBody.isBlank()) {
                return this.mapper.createObjectNode();
            }
            return this.mapper.readTree(responseBody);
        } catch (KuraRestException e) {
            throw e;
        } catch (Exception e) {
            throw new KuraRestException(-1, "Kura REST " + method + " " + path + " failed: " + e.getMessage());
        }
    }

    private static String truncate(String value) {
        return value.length() > 300 ? value.substring(0, 300) + "..." : value;
    }

    private static SSLContext trustAllContext() {
        try {
            TrustManager[] trustAll = new TrustManager[] { new X509TrustManager() {
                @Override
                public void checkClientTrusted(X509Certificate[] chain, String authType) {
                    // accept everything: the gateway certificate is provisioned locally
                }

                @Override
                public void checkServerTrusted(X509Certificate[] chain, String authType) {
                    // accept everything: the gateway certificate is provisioned locally
                }

                @Override
                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[0];
                }
            } };
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, trustAll, new SecureRandom());
            return context;
        } catch (Exception e) {
            throw new IllegalStateException("Unable to init trust-all SSL context", e);
        }
    }
}
