#include "webserver/WebServer.h"
#include "controllers/SmartcardController.h"

static bool keep_alive = true;

void handle_term_signal(int) {
    keep_alive = false;
}

int main(int argc, char **argv) {
    bool foreground_mode = false;
// Check for -f argument for foreground mode
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "-f") == 0) {
            foreground_mode = true;
            break;
        }
    }

    if (!foreground_mode) {
        // Fork and run as a daemon
        pid_t pid = fork();
        if (pid < 0) {
            // Fork failed
            std::cerr << "Failed to fork process" << std::endl;
            return EXIT_FAILURE;
        }
        if (pid > 0) {
            // Exit parent process
            return EXIT_SUCCESS;
        }

        // Create a new session and set the process as group leader
        if (setsid() < 0) {
            std::cerr << "Failed to create a new session" << std::endl;
            return EXIT_FAILURE;
        }

        // Fork again to ensure the process cannot acquire a controlling terminal
        pid = fork();
        if (pid < 0) {
            // Fork failed
            std::cerr << "Failed to fork process (second attempt)" << std::endl;
            return EXIT_FAILURE;
        }
        if (pid > 0) {
            // Exit the first child process
            return EXIT_SUCCESS;
        }

        // Set file permissions mask to avoid inheriting restrictive permissions
        umask(0);

        // Change the working directory to /
        if (chdir("/") < 0) {
            std::cerr << "Failed to change directory to /" << std::endl;
            return EXIT_FAILURE;
        }

        // Redirect standard file descriptors to /dev/null
        freopen("/dev/null", "r", stdin);
        // Redirect stdout to /var/log/nnscproxy.stdout.log
        const char *stdout_log_file = "/var/log/nnscproxy.stdout.log";
        FILE *stdout_log = freopen(stdout_log_file, "a", stdout);
        if (stdout_log == nullptr) {
            std::cerr << "Failed to redirect stdout to log file: " << stdout_log_file << std::endl;
            return EXIT_FAILURE;
        }

        // Alternatively, redirect stderr to the same log file if needed
        const char *stderr_log_file = "/var/log/nnscproxy.stderr.log";
        FILE *stderr_log = freopen(stderr_log_file, "a", stderr);
        if (stderr_log == nullptr) {
            std::cerr << "Failed to redirect stderr to log file: " << stderr_log_file << std::endl;
            return EXIT_FAILURE;
        }

        // Write the PID to /var/run/nnscproxy.pid
        const char *pid_file = "/var/run/nnscproxy.pid";
        FILE *fpid = fopen(pid_file, "w");
        if (fpid == nullptr) {
            std::cerr << "Failed to open PID file: " << pid_file << std::endl;
            return EXIT_FAILURE;
        }
        fprintf(fpid, "%d\n", getpid());
        fclose(fpid);
    }

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