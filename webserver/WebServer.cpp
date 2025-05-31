//
// Created by sigsegv on 20.12.2020.
//

#include "WebServer.h"
#include <boost/algorithm/string.hpp>

template <> std::optional<std::string> handle_path_comp<std::string>(const std::string &path_comp) {
    return { path_comp };
}

WebServer::WebServer(const char *listen_to) :
        listener(listen_to)
{
    listener.support(web::http::methods::OPTIONS, [this] (web::http::http_request request) {
        this->handle_request(request);
    });
    listener.support([this] (web::http::http_request request) {
        this->handle_request(request);
    });
    listener.open();
}

WebServer::~WebServer() {
    listener.close().wait();
}

void WebServer::handle_request(web::http::http_request req) {
    const web::http::uri &uri = req.request_uri();
    std::string path = uri.path();
    auto iterator = path.begin();
    while (iterator != path.end()) {
        if (*iterator != '/')
            break;
        iterator++;
    }
    std::vector<std::string> components{};
    while (iterator != path.end()) {
        auto start = iterator;
        while (*iterator != '/') {
            ++iterator;
            if (iterator == path.end())
                break;
        }
        auto end = iterator;
        while (iterator != path.end() && *iterator == '/') {
            ++iterator;
        }
        std::string item = std::accumulate(start, end, std::string(), [] (std::string str, char ch) -> std::string {
            return std::move(str) + std::string(&ch, 1);
        });
        components.push_back(item);
    }
    std::map<std::string,std::string> query;
    {
        const std::string &q = uri.query();
        query = web::http::uri::split_query(q);
    }
    try {
        for (const auto &handler : handlers) {
            if (!(*handler).isTermination() && (*handler).canTake(components)) {
                std::optional<pplx::task<web::http::http_response>> opt = (*handler).handle(components, query, req);
                if (opt) {
                    opt.value().then([](pplx::task<web::http::http_response> task) {
                        try {
                            return task.get();
                        } catch (std::exception &e) {
                            web::http::http_response response(web::http::status_codes::InternalError);
                            web::json::value value = web::json::value::object();
                            value["error"] = web::json::value(e.what());
                            response.set_body(value);
                            return response;
                        } catch (...) {
                            web::http::http_response response(web::http::status_codes::InternalError);
                            web::json::value value = web::json::value::object();
                            value["error"] = web::json::value("Internal error");
                            response.set_body(value);
                            return response;
                        }
                    }).then([req](const web::http::http_response &response) {
                        req.reply(response);
                    });
                    return;
                }
            }
        }
        for (const auto &handler : handlers) {
            if ((*handler).isTermination() && (*handler).canTake(components)) {
                std::optional<pplx::task<web::http::http_response>> opt = (*handler).handle(components, query, req);
                if (opt) {
                    opt.value().then([](pplx::task<web::http::http_response> task) {
                        try {
                            return task.get();
                        } catch (std::exception &e) {
                            web::http::http_response response(web::http::status_codes::InternalError);
                            web::json::value value = web::json::value::object();
                            value["error"] = web::json::value(e.what());
                            response.set_body(value);
                            return response;
                        } catch (...) {
                            web::http::http_response response(web::http::status_codes::InternalError);
                            web::json::value value = web::json::value::object();
                            value["error"] = web::json::value("Internal error");
                            response.set_body(value);
                            return response;
                        }
                    }).then([req](const web::http::http_response &response) {
                        req.reply(response);
                    });
                    return;
                }
            }
        }
        web::http::http_response response(web::http::status_codes::NotFound);
        web::json::value value = web::json::value::object();
        value["error"] = web::json::value("Not found");
        response.set_body(value);
        req.reply(response);
    } catch (std::exception &e) {
        web::http::http_response response(web::http::status_codes::InternalError);
        web::json::value value = web::json::value::object();
        value["error"] = web::json::value(e.what());
        response.set_body(value);
        req.reply(response);
    } catch (...) {
        web::http::http_response response(web::http::status_codes::InternalError);
        web::json::value value = web::json::value::object();
        value["error"] = web::json::value("Internal error");
        response.set_body(value);
        req.reply(response);
    }
}
