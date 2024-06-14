package com.mdekhtiarenko;

import com.sun.net.httpserver.Authenticator;
import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpContext;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpPrincipal;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;


public class SimpleHttpServer {
    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create();
        server.bind(new InetSocketAddress(8080), 0);

        HttpContext echoContext = server.createContext("/login", new EchoHandler());
//        echoContext.setAuthenticator(new Auth());

        HttpContext helloWorldContext = server.createContext("/hello", exchange -> {

            System.out.println(exchange.getRequestMethod());
            System.out.println(exchange.getRequestURI());

            byte[] response = """
                    {
                        "id" : 1
                        "manage" : "something"
                    }
                    """.getBytes();
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, response.length);

            OutputStream os = exchange.getResponseBody();

            os.write(response);
            os.close();
        });
        helloWorldContext.setAuthenticator(new Auth());

        server.setExecutor(null);
        server.start();
    }

    static class EchoHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            StringBuilder builder = new StringBuilder();

            builder.append("<h1>URI: ").append(exchange.getRequestURI()).append("</h1>");

            Headers headers = exchange.getRequestHeaders();
            for (String header : headers.keySet()) {
                builder.append("<p>").append(header).append("=")
                        .append(headers.getFirst(header)).append("</p>");
            }

            byte[] bytes = builder.toString().getBytes();
            exchange.sendResponseHeaders(200, bytes.length);

            OutputStream os = exchange.getResponseBody();
            os.write(bytes);
            os.close();
        }
    }

    static class Auth extends Authenticator {
        @Override
        public Result authenticate(HttpExchange httpExchange) {

            var jwtToken = httpExchange.getRequestHeaders().getFirst("Authorization");

            if (jwtToken == null || !isValidJWT(jwtToken)) {
                return new Failure(401);
            }

            //TODO: get data for HttpPrincipal from actual jwt token
            return new Success(new HttpPrincipal("johndoe", ""));
        }
    }

    private static boolean isValidJWT(String jwtToken) {
        //TODO: make it work
        return true;
    }
}
