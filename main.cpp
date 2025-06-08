#include "webserver/WebServer.h"
#include "controllers/SmartcardController.h"

static bool keep_alive = true;

void handle_term_signal(int) {
    keep_alive = false;
}

int main() {
    std::string listen{};
    {
        auto smartcardController = std::make_shared<SmartcardController>();
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
        webServer / "scard" / "list" >> [smartcardController] web_handler (web::http::http_request &req) {
            return handle_web ([smartcardController] async_web {
                web::http::http_response response(web::http::status_codes::OK);
                auto readers = smartcardController->GetReaders();
                auto resp = web::json::value::object();
                resp["errorcode"] = web::json::value::number(0);
                resp["errordetail"] = web::json::value::number(0);
                auto readerArray = web::json::value::array(readers.size());
                decltype(readers.size()) i = 0;
                for (const auto &reader : readers) {
                    auto readerObject = web::json::value::object();
                    readerObject["cardstatus"] = web::json::value::number(302);
                    readerObject["name"] = web::json::value::string(reader);
                    readerArray[i++] = readerObject;
                }
                resp["readers"] = readerArray;
                response.set_body(resp);
                return response;
            });
        };
        webServer / "scard" / "apdu" / PathVariable<std::string>() >> [smartcardController] web_handler (web::http::http_request &req, const std::string &cardReader) {
            std::string cardReaderDecoded = web::uri::decode(cardReader);
            pplx::task<web::json::value> json = req.extract_json(true);
            pplx::task<web::http::http_response> response = json.then([smartcardController, cardReader = std::move(cardReaderDecoded)] (const pplx::task<web::json::value> &req) -> web::http::http_response {
                web::json::value jsonreq;
                try {
                    jsonreq = req.get();
                } catch (...) {
                    std::cerr << "Apdu: Request json read failed\n";
                    web::http::http_response response{web::http::status_codes::BadRequest};
                    return response;
                }
                std::string session;
                std::vector<std::string> apdu;
                if (jsonreq.has_string_field("session")) {
                    session = jsonreq.at("session").as_string();
                }
                if (jsonreq.has_array_field("apducommands")) {
                    auto arr = jsonreq.at("apducommands").as_array();
                    for (const auto &obj : arr) {
                        if (!obj.is_object() || !obj.has_string_field("apdu")) {
                            std::cerr << "Apdu: Invalid apdu command\n";
                            web::http::http_response response{web::http::status_codes::BadRequest};
                            return response;
                        }
                        apdu.emplace_back(obj.at("apdu").as_string());
                    }
                }
                auto apdures = smartcardController->RunApdu(cardReader, session, apdu);
                web::http::http_response response{web::http::status_codes::OK};
                auto resp = web::json::value::object();
                resp["errorcode"] = web::json::value::number(0);
                resp["errordetail"] = web::json::value::number(0);
                auto arr = web::json::value::array(apdures.size());
                decltype(apdures.size()) i = 0;
                for (const auto &res : apdures) {
                    auto obj = web::json::value::object();
                    obj["apdu"] = web::json::value::string(res);
                    arr[i++] = obj;
                }
                resp["apduresponses"] = arr;
                response.set_body(resp);
                return response;
            });
            return response;
        };
        webServer / "scard" / "disconnect" >> [smartcardController] web_handler (web::http::http_request &req) {
            pplx::task<web::json::value> json = req.extract_json(true);
            pplx::task<web::http::http_response> response = json.then([smartcardController] (const pplx::task<web::json::value> &req) -> web::http::http_response {
                web::json::value jsonreq;
                try {
                    jsonreq = req.get();
                } catch (...) {
                    std::cerr << "Disconnect: Request json read failed\n";
                    web::http::http_response response{web::http::status_codes::BadRequest};
                    return response;
                }
                std::string session;
                std::vector<std::string> apdu;
                if (jsonreq.has_string_field("session")) {
                    session = jsonreq.at("session").as_string();
                }
                smartcardController->Disconnect(session);
                web::http::http_response response{web::http::status_codes::OK};
                return response;
            });
            return response;
        };
        webServer / "scard" / "getref" >> [smartcardController] web_handler (web::http::http_request &req) {
            return handle_web ([smartcardController] async_web {
                auto ref = smartcardController->GetRef();
                web::http::http_response response{web::http::status_codes::OK};
                auto json = web::json::value::object();
                json["data"] = web::json::value::string(ref.key);
                json["ref"] = web::json::value::number(ref.ref);
                response.set_body(json);
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