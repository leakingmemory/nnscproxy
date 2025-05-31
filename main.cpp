#include <iostream>
#include "webserver/WebServer.h"

static bool keep_alive = true;

void handle_term_signal(int) {
    keep_alive = false;
}

int main() {
    std::string listen{};
    {
        const char *listen = getenv("LISTEN");
        if (listen == NULL) {
            listen = "http://127.0.0.1:32505";
        }

        WebServer webServerInstance(listen);

        auto &webServer = webServerInstance;

        webServer / "scard" / "version" >> [] web_handler (web::http::http_request &req) {
            return handle_web ([] async_web {
                web::http::http_response response(web::http::status_codes::OK);
                web::json::value value = web::json::value::object();
                value["version"] = web::json::value("1.5.2");
                response.set_body(value);
                return response;
            });
        };

        signal(SIGINT, handle_term_signal);
        signal(SIGTERM, handle_term_signal);

        while (keep_alive) {
            sleep(1);
        }
    }
}