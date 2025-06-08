//
// Created by sigsegv on 6/8/25.
//

#ifndef NNSCPROXY_SMARTCARDCONTROLLER_H
#define NNSCPROXY_SMARTCARDCONTROLLER_H

#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <thread>
#include <semaphore>
#include <optional>

struct SmartcardKeyRef {
    std::string key;
    uint64_t ref;
};

class SmartcardController {
private:
    std::map<uint64_t,std::string> refs{};
    std::map<std::string,std::unique_ptr<std::thread>> threads{};
    std::map<std::string,std::string> session{};
    std::map<std::string,std::vector<std::string>> input{};
    std::map<std::string,std::shared_ptr<std::counting_semaphore<255>>> delivery{};
    std::map<std::string,std::shared_ptr<std::counting_semaphore<255>>> product{};
    std::map<std::string,std::vector<std::string>> output{};
    std::vector<std::string> stop{};
    std::mutex mtx{};
public:
    std::vector<std::string> GetReaders();
    void RunReader(const std::string &reader);
    bool TakeReader(const std::string &reader, const std::string &session);
    static constexpr std::string ToBinary(const std::string &hex);
    static constexpr std::string FromBinary(const std::string &binary);
    std::optional<std::string> GetReader(const std::string &session);
    std::vector<std::string> PinCmd(const std::string &scrambled);
    std::vector<std::string> RunApdu(const std::string &reader, const std::string &session, const std::vector<std::string> &commands);
    void Disconnect(const std::string &session);
    SmartcardKeyRef GetRef();
};


#endif //NNSCPROXY_SMARTCARDCONTROLLER_H
