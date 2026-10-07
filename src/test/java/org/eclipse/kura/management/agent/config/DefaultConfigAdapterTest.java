package org.eclipse.kura.management.agent.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import org.eclipse.kura.management.agent.model.ConfigDescriptor;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

class DefaultConfigAdapterTest {

    private HttpServer server;
    private DefaultConfigAdapter adapter;
    private final AtomicReference<String> lastMethod = new AtomicReference<>();
    private final AtomicReference<String> lastPath = new AtomicReference<>();
    private final AtomicReference<String> lastBody = new AtomicReference<>("");

    @BeforeEach
    void setUp() throws IOException {
        this.server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        this.server.createContext("/", (HttpExchange exchange) -> {
            this.lastMethod.set(exchange.getRequestMethod());
            this.lastPath.set(exchange.getRequestURI().getPath());
            this.lastBody.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            byte[] response = responseBody(exchange.getRequestURI().getPath());
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, response.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(response);
            }
        });
        this.server.start();
        System.setProperty("kura.rest.baseUrl",
                "http://localhost:" + this.server.getAddress().getPort());
        this.adapter = new DefaultConfigAdapter(new KuraRestClient());
    }

    @AfterEach
    void tearDown() {
        this.server.stop(0);
        System.clearProperty("kura.rest.baseUrl");
    }

    private byte[] responseBody(String path) {
        return switch (path) {
            case "/configuration/v2/snapshots" -> "{\"ids\":[3,2,1]}".getBytes(StandardCharsets.UTF_8);
            case "/configuration/v2/configurableComponents/pidsWithFactory" ->
                "{\"components\":[{\"pid\":\"org.example.service\",\"factoryPid\":\"org.example.factory\"}]}".getBytes(StandardCharsets.UTF_8);
            case "/configuration/v2/configurableComponents/configurations/byPid" ->
                "{\"configurations\":[{\"pid\":\"org.example.service\",\"properties\":[]}]}".getBytes(StandardCharsets.UTF_8);
            case "/configuration/v2/snapshots/_write" -> "{\"id\":9}".getBytes(StandardCharsets.UTF_8);
            case "/configuration/v2/snapshots/byId/_rollback" -> "{\"id\":10}".getBytes(StandardCharsets.UTF_8);
            case "/configuration/v2/snapshots/_rollback" -> "{\"id\":11}".getBytes(StandardCharsets.UTF_8);
            default -> "{}".getBytes(StandardCharsets.UTF_8);
        };
    }

    @Test
    void listConfigsParsesComponents() {
        List<ConfigDescriptor> configs = this.adapter.listConfigs();
        assertEquals(1, configs.size());
        assertEquals("org.example.service", configs.get(0).pid());
        assertEquals("org.example.factory", configs.get(0).factoryPid());
        assertTrue(configs.get(0).isFactoryConfigured());
        assertEquals("GET", this.lastMethod.get());
        assertEquals("/configuration/v2/configurableComponents/pidsWithFactory", this.lastPath.get());
    }

    @Test
    void getConfigPostsPidSet() {
        var configuration = this.adapter.getConfig("org.example.service");
        assertEquals("org.example.service", configuration.path("configurations").get(0).path("pid").asText());
        assertEquals("POST", this.lastMethod.get());
        assertTrue(this.lastBody.get().contains("org.example.service"));
    }

    @Test
    void updateConfigPutsComponentConfigurationList() {
        this.adapter.updateConfig("org.example.service",
                java.util.Map.of("pid", "org.example.service", "properties", List.of()));
        assertEquals("PUT", this.lastMethod.get());
        assertEquals("/configuration/v2/configurableComponents/configurations/_update", this.lastPath.get());
        assertTrue(this.lastBody.get().contains("\"configurations\""));
    }

    @Test
    void snapshotOperationsParseIds() {
        assertEquals(9L, this.adapter.takeSnapshot().snapshotId());
        assertEquals(List.of(3L, 2L, 1L), this.adapter.listSnapshots());
        assertEquals(10L, this.adapter.rollback(3L).snapshotId());
        assertTrue(this.lastBody.get().contains("\"id\""));
        assertEquals(11L, this.adapter.rollback(null).snapshotId());
        assertEquals("/configuration/v2/snapshots/_rollback", this.lastPath.get());
    }

    @Test
    void restErrorSurfacesAsException() {
        this.server.removeContext("/");
        this.server.createContext("/", (HttpExchange exchange) -> {
            byte[] response = "{\"message\":\"nope\"}".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(500, response.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(response);
            }
        });
        assertThrows(KuraRestClient.KuraRestException.class, this.adapter::listSnapshots);
    }
}
