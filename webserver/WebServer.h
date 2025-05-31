//
// Created by sigsegv on 20.12.2020.
//

#ifndef CURRENCY_WEBSERVER_H
#define CURRENCY_WEBSERVER_H

#include <cpprest/http_listener.h>
#include <memory>
#include <vector>
#include <boost/algorithm/string.hpp>

template <typename... Args> class PathHandler {
public:
    virtual bool isTermination() {
        return true;
    }
    virtual std::optional<std::string> getPathComp() {
        return {};
    }
    virtual bool canTake(const std::vector<std::string> &path) {
        return true;
    }
    virtual std::optional<pplx::task<web::http::http_response>> handle(const std::vector<std::string> &path, const std::map<std::string,std::string> &query, Args... args) = 0;
};

template <typename... Args> class TerminationHandler : public PathHandler<Args...> {
private:
    std::function<pplx::task<web::http::http_response> (Args...)> func;
public:
    explicit TerminationHandler(std::function<pplx::task<web::http::http_response> (Args...)> func) :
            func(func) {
    }

    bool canTake(const std::vector<std::string> &path) override {
        return path.empty();
    }

    std::optional<pplx::task<web::http::http_response>> handle(const std::vector<std::string> &path, const std::map<std::string,std::string> &query, Args... args) override {
        return { func(args...) };
    }
};

template <typename T> class QueryParam {
private:
    std::string name;
    T defaultValue;
public:
    QueryParam(const std::string &name, const T &dfeultValue) : name(name), defaultValue(defaultValue) {}
    QueryParam(const std::string &name, T &&defaultValue) : name(name), defaultValue(std::move(defaultValue)) {}
    const std::string &getName() const {
        return name;
    }
    const T &getDefaultValue() const {
        return defaultValue;
    }
};

template <typename T, typename... Args> class QueryParamHandler;

template <typename T> class PathVariable {
};

template <typename T, typename... Args> class ParamComp;

template <typename... Args> class ByPathComp;

template <typename... Args> class WebFilter {
public:
    virtual ~WebFilter() = default;
    virtual std::optional<pplx::task<web::http::http_response>> filter(std::function<std::optional<pplx::task<web::http::http_response>> (Args...)>, const std::vector<std::string> &path, const std::map<std::string,std::string> &query, Args...) = 0;
};

template <typename Filter, typename... Args> class FilterHandler : public PathHandler<Args...> {
private:
    std::vector<std::shared_ptr<PathHandler<Args...>>> path_handlers;
    Filter filter;
public:
    explicit FilterHandler(const Filter &filter) : path_handlers{}, filter(filter) {
        static_assert(std::is_base_of<WebFilter<Args...>, Filter>::value);
    }

    template<class V> V &add_path_handler(const V &pathHandler) {
        static_assert(std::is_base_of<PathHandler<Args...>, V>::value);
        std::shared_ptr<V> ptr = std::make_shared<V>(pathHandler);
        path_handlers.push_back(ptr);
        return *ptr;
    }

    bool isTermination() override {
        return false;
    }

    bool canTake(const std::vector<std::string> &path) override {
        bool canTake = false;
        for (std::shared_ptr<PathHandler<Args...>> handler : path_handlers) {
            if ((*handler).canTake(path)) {
                canTake = true;
                break;
            }
        }
        return canTake;
    }

    std::optional<pplx::task<web::http::http_response>> handle(const std::vector<std::string> &path, const std::map<std::string,std::string> &query, Args... args) override {
        return filter.filter(
                [this, &path, &query](Args... args) -> std::optional<pplx::task<web::http::http_response>> {
                    for (auto handler : path_handlers) {
                        if (!(*handler).isTermination() && (*handler).canTake(path)) {
                            std::optional<pplx::task<web::http::http_response>> opt = (*handler).handle(path, query, args...);
                            if (opt) {
                                return opt;
                            }
                        }
                    }
                    for (auto handler : path_handlers) {
                        if ((*handler).isTermination() && (*handler).canTake(path)) {
                            std::optional<pplx::task<web::http::http_response>> opt = (*handler).handle(path, query, args...);
                            if (opt) {
                                return opt;
                            }
                        }
                    }
                    return { };
                }, path, query, args...);
    }

    template <class V> V &operator / (const V &handler) {
        return add_path_handler(handler);
    }
    ByPathComp<Args...> &operator / (const std::string &pcomp) {
        return add_path_handler(ByPathComp<Args...>(pcomp));
    }
    ByPathComp<Args...> &operator / (const char *pcomp) {
        return add_path_handler(ByPathComp<Args...>(pcomp));
    }

    template <typename V> ParamComp<V, Args...> &operator / (const PathVariable<V> &pv) {
        return add_path_handler(ParamComp<V, Args...>());
    }

    template <typename SubFilter> FilterHandler<SubFilter,web::http::http_request &> &operator | (const SubFilter &filter) {
        return *this / FilterHandler<SubFilter,web::http::http_request &>(filter);
    }

    template <typename V> QueryParamHandler<V, Args...> &operator & (const QueryParam<V> &param) {
        return add_path_handler(QueryParamHandler<V, Args...>(param.getName(), param.getDefaultValue()));
    }

    QueryParamHandler<std::string, Args...> &operator & (const std::string &name) {
        return *this & QueryParam<std::string>(name, std::string());
    }

    QueryParamHandler<std::string, Args...> &operator & (const char *name) {
        return *this & std::string(name);
    }

    TerminationHandler<Args...> &operator >> (const std::function<pplx::task<web::http::http_response> (Args...)> &func) {
        return add_path_handler(TerminationHandler<Args...>(func));
    }
};

template <typename T> std::optional<T> handle_path_comp(const std::string &);

template <typename T, typename... Args> class QueryParamHandler : public PathHandler<Args...> {
private:
    std::string name;
    T defaultValue;
    std::vector<std::shared_ptr<PathHandler<Args..., T>>> query_handlers;
public:
    QueryParamHandler(const std::string &name, const T &defaultValue) : name(name), defaultValue(defaultValue), query_handlers() {
        boost::to_lower(this->name);
    }
    QueryParamHandler(const char *name, const T &defaultValue) : name(name), defaultValue(defaultValue), query_handlers() {
        boost::to_lower(this->name);
    }
    QueryParamHandler(const std::string &name, T &&defaultValue) : name(name), defaultValue(defaultValue), query_handlers() {
        boost::to_lower(this->name);
    }
    QueryParamHandler(const char *name, T &&defaultValue) : name(name), defaultValue(defaultValue), query_handlers() {
        boost::to_lower(this->name);
    }

    template<class V> V &add_path_handler(const V &pathHandler) {
        static_assert(std::is_base_of<PathHandler<Args..., T>, V>::value);
        std::shared_ptr<V> ptr = std::make_shared<V>(pathHandler);
        query_handlers.push_back(ptr);
        return *ptr;
    }

    bool isTermination() override {
        return false;
    }
    std::optional<std::string> getPathComp() {
        return { };
    }
    bool canTake(const std::vector<std::string> &path) override {
        return path.empty();
    }

    T getQueryParam(const std::map<std::string,std::string> &query) {
        auto iterator = query.find(name);
        if (iterator != query.end()) {
            return handle_path_comp<T>(iterator->second).value_or(defaultValue);
        } else {
            return defaultValue;
        }
    }

    std::optional<pplx::task<web::http::http_response>> handle(const std::vector<std::string> &path, const std::map<std::string,std::string> &query, Args... args) {
        T value = getQueryParam(query);
        for (auto handler : query_handlers) {
            if (!(*handler).isTermination() && (*handler).canTake(path)) {
                std::optional<pplx::task<web::http::http_response>> opt = (*handler).handle(path, query, args..., value);
                if (opt) {
                    return opt;
                }
            }
        }
        for (auto handler : query_handlers) {
            if ((*handler).isTermination() && (*handler).canTake(path)) {
                std::optional<pplx::task<web::http::http_response>> opt = (*handler).handle(path, query, args..., value);
                if (opt) {
                    return opt;
                }
            }
        }
        return {};
    }

    template <typename V> QueryParamHandler<V, Args..., T> &operator & (const QueryParam<V> &param) {
        return add_path_handler(QueryParamHandler<V, Args..., T>(param.getName(), param.getDefaultValue()));
    }

    QueryParamHandler<std::string, Args..., T> &operator & (const std::string &name) {
        return *this & QueryParam<std::string>(name, std::string());
    }

    QueryParamHandler<std::string, Args..., T> &operator & (const char *name) {
        return *this & std::string(name);
    }

    template <typename Filter> FilterHandler<Filter, Args..., T> &operator | (const Filter &filter) {
        return add_path_handler(FilterHandler<Filter, Args..., T>(filter));
    }

    TerminationHandler<Args..., T> &operator >> (const std::function<pplx::task<web::http::http_response> (Args..., T)> &func) {
        return add_path_handler(TerminationHandler<Args..., T>(func));
    }
};

template <typename... Args> class ByPathComp : public PathHandler<Args...> {
private:
    std::string path_comp;
    std::vector<std::shared_ptr<PathHandler<Args...>>> path_handlers;
public:
    ByPathComp(const std::string &path_comp) : path_comp(path_comp), path_handlers() {
        boost::to_lower(this->path_comp);
    }
    ByPathComp(const char *path_comp) : path_comp(path_comp), path_handlers() {
        boost::to_lower(this->path_comp);
    }
    template<class V> void add_path_handler(const V &pathHandler) {
        static_assert(std::is_base_of<PathHandler<Args...>, V>::value);
        path_handlers.push_back(std::make_shared<V>(pathHandler));
    }

    bool isTermination() override {
        return false;
    }
    std::optional<std::string> getPathComp() {
        return { path_comp };
    }
    bool canTake(const std::vector<std::string> &path) override {
        auto iterator = path.begin();
        if (iterator == path.end()) {
            return false;
        }
        return (boost::to_lower_copy(*iterator) == path_comp);
    }

    std::optional<pplx::task<web::http::http_response>> handle(const std::vector<std::string> &path, const std::map<std::string,std::string> &query, Args... args) {
        std::vector<std::string> rest_of_path{};
        {
            auto iterator = path.begin();
            iterator++;
            while (iterator != path.end()) {
                rest_of_path.push_back(*iterator);
                iterator++;
            }
        }
        for (auto handler : path_handlers) {
            if (!(*handler).isTermination() && (*handler).canTake(rest_of_path)) {
                std::optional<pplx::task<web::http::http_response>> opt = (*handler).handle(rest_of_path, query, args...);
                if (opt) {
                    return opt;
                }
            }
        }
        for (auto handler : path_handlers) {
            if ((*handler).isTermination() && (*handler).canTake(rest_of_path)) {
                std::optional<pplx::task<web::http::http_response>> opt = (*handler).handle(rest_of_path, query, args...);
                if (opt) {
                    return opt;
                }
            }
        }
        return {};
    }

    template <class V> V &operator / (const V &handler) {
        static_assert(std::is_base_of<PathHandler<Args...>, V>::value);
        auto shptr = std::make_shared<V>(handler);
        path_handlers.push_back(shptr);
        return *shptr;
    }
    ByPathComp<Args...> &operator / (const std::string &pcomp) {
        for (auto handler : path_handlers) {
            std::optional<std::string> comp = (*handler).getPathComp();
            if (comp && comp.value() == pcomp) {
                return dynamic_cast<ByPathComp<Args...> &>(*handler);
            }
        }
        return *this / ByPathComp<Args...>(pcomp);
    }
    ByPathComp<Args...> &operator / (const char *pcomp) {
        return *this / std::string(pcomp);
    }
    template <typename T> ParamComp<T, Args...> &operator / (const PathVariable<T> &pv) {
        return *this / ParamComp<T, Args...>();
    }

    template <typename T> QueryParamHandler<T, Args...> &operator & (const QueryParam<T> &param) {
        return *this / QueryParamHandler<T>(param.getName(), param.defaultValue());
    }

    QueryParamHandler<std::string, Args...> &operator & (const std::string &name) {
        return *this & QueryParam<std::string>(name, std::string());
    }

    QueryParamHandler<std::string, Args...> &operator & (const char *name) {
        return *this & std::string(name);
    }

    template <typename Filter> FilterHandler<Filter, Args...> &operator | (const Filter &filter) {
        return *this / FilterHandler<Filter, Args...>(filter);
    }

    TerminationHandler<Args...> &operator >> (const std::function<pplx::task<web::http::http_response> (Args...)> &func) {
        return *this / TerminationHandler<Args...>(func);
    }
};

template <typename T, typename... Args> class ParamComp : public PathHandler<Args...> {
private:
    std::vector<std::shared_ptr<PathHandler<Args..., T>>> path_handlers;
public:
    template <class V> void add_path_handler(const V &pathHandler) {
        static_assert(std::is_base_of<PathHandler<Args..., T>,V>::value);
        path_handlers.push_back(std::make_shared<V>(pathHandler));
    }

    bool isTermination() override {
        return false;
    }
    std::optional<std::string> getPathComp() {
        return { };
    }
    bool canTake(const std::vector<std::string> &path) override {
        auto iterator = path.begin();
        if (iterator == path.end()) {
            return false;
        }
        try {
            if (handle_path_comp<T>(*iterator)) {
                return true;
            }
        } catch (...) {
        }
        return false;
    }

    std::optional<pplx::task<web::http::http_response>> handle(const std::vector<std::string> &path, const std::map<std::string,std::string> &query, Args... args) override {
        std::vector<std::string> rest_of_path{};
        std::string path_comp;
        {
            auto iterator = path.begin();
            path_comp = *iterator;
            iterator++;
            while (iterator != path.end()) {
                rest_of_path.push_back(*iterator);
                iterator++;
            }
        }
        for (auto handler : path_handlers) {
            if (!(*handler).isTermination() && (*handler).canTake(rest_of_path)) {
                std::optional<pplx::task<web::http::http_response>> opt = (*handler).handle(rest_of_path, query, args..., handle_path_comp<T>(path_comp).value());
                if (opt) {
                    return opt;
                }
            }
        }
        for (auto handler : path_handlers) {
            if ((*handler).isTermination() && (*handler).canTake(rest_of_path)) {
                std::optional<pplx::task<web::http::http_response>> opt = (*handler).handle(rest_of_path, query, args..., handle_path_comp<T>(path_comp).value());
                if (opt) {
                    return opt;
                }
            }
        }
        return {};
    }

    template <class V> V &operator / (const V &handler) {
        add_path_handler(handler);
        PathHandler<Args..., T> &ref = *(path_handlers.back());
        return dynamic_cast<V &>(ref);
    }
    ByPathComp<Args..., T> &operator / (const std::string &pcomp) {
        return *this / ByPathComp<Args..., T>(pcomp);
    }
    ByPathComp<Args..., T> &operator / (const char *pcomp) {
        return *this / ByPathComp<Args..., T>(pcomp);
    }
    template <typename V> ParamComp<V, Args..., T> &operator / (const PathVariable<V> &pv) {
        return *this / ParamComp<V, Args..., T>();
    }

    template <typename V> QueryParamHandler<V, Args..., T> &operator & (const QueryParam<V> &param) {
        return *this / QueryParamHandler<V, Args..., T>(param.getName(), param.getDefaultValue());
    }

    QueryParamHandler<std::string, Args..., T> &operator & (const std::string &name) {
        return *this & QueryParam<std::string>(name, std::string());
    }

    QueryParamHandler<std::string, Args..., T> &operator & (const char *name) {
        std::string n{name};
        return *this & n;
    }

    template <typename Filter> FilterHandler<Filter, Args..., T> &operator | (const Filter &filter) {
        return *this / FilterHandler<Filter, Args..., T>(filter);
    }

    TerminationHandler<Args..., T> &operator >> (const std::function<pplx::task<web::http::http_response> (Args..., T)> &func) {
        return *this / TerminationHandler<Args..., T>(func);
    }
};

class WebServer {
private:
    web::http::experimental::listener::http_listener listener;
    std::vector<std::shared_ptr<PathHandler<web::http::http_request &>>> handlers;
public:
    explicit WebServer(const char *listen_to);
    ~WebServer();
    template<class T> void add_handler(const T &handler) {
        static_assert(std::is_base_of<PathHandler<web::http::http_request &>,T>::value);
        handlers.push_back(std::make_shared<T>(handler));
    }
    template<class T> T &operator / (const T &handler) {
        static_assert(std::is_base_of<PathHandler<web::http::http_request &>,T>::value);
        auto shptr = std::make_shared<T>(handler);
        handlers.emplace_back(shptr);
        return *shptr;
    }
    ByPathComp<web::http::http_request &> &operator / (const std::string &pcomp) {
        for (auto handler : handlers) {
            std::optional<std::string> comp = (*handler).getPathComp();
            if (comp && comp.value() == pcomp) {
                auto &ref = *handler;
                return dynamic_cast<ByPathComp<web::http::http_request &>&>(ref);
            }
        }
        return *this / ByPathComp<web::http::http_request &>(pcomp);
    }
    ByPathComp<web::http::http_request &> &operator / (const char *pcomp) {
        return *this / std::string(pcomp);
    }

    template <typename Filter> FilterHandler<Filter,web::http::http_request &> &operator | (const Filter &filter) {
        return *this / FilterHandler<Filter,web::http::http_request &>(filter);
    }
private:
    void handle_request(web::http::http_request req);
};

#define handle_web pplx::task<web::http::http_response>
#define web_handler(...) (__VA_ARGS__) -> handle_web
#define async_web () -> web::http::http_response


#endif //ELPRICE_WEBSERVER_H
