//
// Created by sigsegv on 6/8/25.
//

#include <PCSC/winscard.h>
#include <PCSC/wintypes.h>
#include "SmartcardController.h"
#include <random>
#include <iostream>

std::vector<std::string> SmartcardController::GetReaders() {
    std::cout << "Get readers\n";
    std::vector<std::string> readersVec{};
    SCARDCONTEXT ctx;
    LONG rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, nullptr, nullptr, &ctx);
    if (rv != SCARD_S_SUCCESS) {
        std::cerr << "SCardEstablishContext() failed: " << std::hex << rv << std::dec << ": " << pcsc_stringify_error(rv) << "\n";
        return {};
    }
    // --- list readers ---
    DWORD len = SCARD_AUTOALLOCATE;
    char *readers = nullptr;
    SCardListReaders(ctx, nullptr, (LPSTR)&readers, &len);

    readersVec = { readers };

    SCardFreeMemory(ctx, readers);
    SCardReleaseContext(ctx);

    std::cout << "Resp readers:\n";
    for (const auto &reader : readersVec) {
        std::cout << "Reader: " << reader << "\n";
    }
    std::cout << "Done resp readers\n";

    return readersVec;
}

void SmartcardController::RunReader(const std::string &reader) {
    SCARDCONTEXT ctx;
    LONG rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, nullptr, nullptr, &ctx);
    if (rv != SCARD_S_SUCCESS) {
        std::cerr << "SCardEstablishContext() failed: " << std::hex << rv << std::dec << ": " << pcsc_stringify_error(rv) << "\n";
        return;
    }
    SCARDHANDLE card;
    DWORD proto;
    SCardConnect(ctx, reader.c_str(), SCARD_SHARE_SHARED,
                 SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
                 &card, &proto);
    while (true) {
        std::shared_ptr<std::counting_semaphore<255>> delivery{};
        {
            std::lock_guard lock{mtx};
            delivery = this->delivery[reader];
        }
        delivery->acquire();
        std::string apdu{};
        {
            std::lock_guard lock{mtx};
            auto stopcmd = std::find(stop.cbegin(), stop.cend(), reader);
            if (stopcmd != stop.cend()) {
                stopcmd = stop.erase(stopcmd);
                break;
            }
            auto iterator = input[reader].begin();
            if (iterator == input[reader].end()) {
                break;
            }
            apdu = *iterator;
            iterator = input[reader].erase(iterator);
        }

        if (apdu.size() > 5 && apdu[0] == static_cast<char>(0xA0) && apdu[1] == 0x20 && apdu[2] == 0 && apdu[3] == static_cast<char>(0x82) && apdu[4] == 8) {
            std::cout << "APDU req: pin req not logged\n";
        } else {
            std::cout << "APDU req: " << FromBinary(apdu) << "\n";
        }

        uint8_t rsp[258];  DWORD rlen = sizeof(rsp);

        const SCARD_IO_REQUEST *sendPci = (proto == SCARD_PROTOCOL_T1) ? SCARD_PCI_T1 : SCARD_PCI_T0;
        SCARD_IO_REQUEST recvPci = {proto, sizeof(SCARD_IO_REQUEST)};

        rv = SCardTransmit(card, sendPci, reinterpret_cast<uint8_t *>(apdu.data()), apdu.size(), &recvPci, rsp, &rlen);
        if (rv == SCARD_S_SUCCESS) {
            apdu = std::string(reinterpret_cast<char *>(rsp), rlen);
            std::cout << "APDU Resp: " << FromBinary(apdu) << "\n";
            if (apdu.size() == 2 && apdu[0] == 0x61) {
                std::string cumulative{};
                while (apdu.size() > 1 && apdu[apdu.size() - 2] == 0x61) {
                    cumulative.append(apdu.c_str(), apdu.size() - 2);
                    apdu = std::string({0x00, static_cast<char>(0xC0), 0x00, 0x00, apdu[1]}, 0, 5);
                    std::cout << "APDU req: " << FromBinary(apdu) << " (data request)\n";
                    rlen = sizeof(rsp);
                    rv = SCardTransmit(card, sendPci, reinterpret_cast<uint8_t *>(apdu.data()), apdu.size(), &recvPci, rsp, &rlen);
                    if (rv == SCARD_S_SUCCESS) {
                        apdu = std::string(reinterpret_cast<char *>(rsp), rlen);
                        std::cout << "APDU Resp: " << FromBinary(apdu) << "\n";
                    } else {
                        apdu = "";
                        std::cerr << "APDU failed " << std::hex << rv << std::dec << "\n";
                    }
                }
                cumulative.append(apdu);
                apdu = cumulative;
                std::cout << "Cumulative: " << FromBinary(apdu) << "\n";
            }
        } else {
            apdu = "";
            std::cerr << "APDU failed " << std::hex << rv << std::dec << "\n";
        }

        std::lock_guard lock{mtx};
        output[reader].emplace_back(apdu);
        product[reader]->release();
    }
    SCardDisconnect(card, SCARD_LEAVE_CARD);
    SCardReleaseContext(ctx);
}

bool SmartcardController::TakeReader(const std::string &reader, const std::string &session) {
    {
        auto iterator = this->session.find(reader);
        if (iterator != this->session.end()) {
            if (iterator->second == session) {
                update_activity_timestamp(reader);
                return true;
            } else if (is_connection_timed_out(reader)) {
                std::cout << "Reader " << reader << " session " << iterator->second << " timed out, recycling\n";
                stop.emplace_back(reader);
                delivery[reader]->release();
                return false;
            }
        }
    }
    this->session.insert_or_assign(reader, session);
    input.insert_or_assign(reader, std::vector<std::string>());
    delivery.insert_or_assign(reader, std::make_shared<std::counting_semaphore<255>>(0));
    product.insert_or_assign(reader, std::make_shared<std::counting_semaphore<255>>(0));
    output.insert_or_assign(reader, std::vector<std::string>());
    auto iterator = threads.find(reader);
    if (iterator != threads.end()) {
        iterator->second->join();
    }
    threads.insert_or_assign(reader, std::make_unique<std::thread>([this, reader] () {
        std::cout << "Opening reader: " << reader << "\n";
        RunReader(reader);
        std::cout << "Closed reader: " << reader << "\n";
        std::lock_guard lock{mtx};
        output.erase(reader);
        product.erase(reader);
        delivery.erase(reader);
        input.erase(reader);
        this->session.erase(reader);
    }));
    update_activity_timestamp(reader);
    return true;
}

std::optional<std::string> SmartcardController::GetReader(const std::string &session) {
    for (const auto &sess : this->session) {
        if (sess.second == session) {
            return sess.first;
        }
    }
    return {};
}

constexpr std::string SmartcardController::ToBinary(const std::string &hex) {
    std::string bin{};
    bin.resize((hex.size() >> 1) + (hex.size() & 1));
    auto iterator = hex.cbegin();
    for (auto &output : bin) {
        unsigned char upper = *iterator;
        ++iterator;
        if (upper >= '0' && upper <= '9') {
            upper = upper - '0';
        } else if (upper >= 'a' && upper <= 'f') {
            upper = upper - 'a' + 10;
        } else if (upper >= 'A' && upper <= 'F') {
            upper = upper - 'A' + 10;
        } else {
            upper = 0;
        }
        unsigned char lower;
        if (iterator != hex.cend()) {
            lower = *iterator;
            ++iterator;
        } else {
            lower = 0;
        }
        if (lower >= '0' && lower <= '9') {
            lower = lower - '0';
        } else if (lower >= 'a' && lower <= 'f') {
            lower = lower - 'a' + 10;
        } else if (lower >= 'A' && lower <= 'F') {
            lower = lower - 'A' + 10;
        } else {
            lower = 0;
        }
        output = static_cast<char>((upper << 4) + lower);
    }
    return bin;
}

static_assert(SmartcardController::ToBinary("") == "");
static_assert(SmartcardController::ToBinary("9") == "\x90");
static_assert(SmartcardController::ToBinary("90") == "\x90");
static_assert(SmartcardController::ToBinary("90C") == "\x90\xC0");
static_assert(SmartcardController::ToBinary("90C1") == "\x90\xC1");
static_assert(SmartcardController::ToBinary("90c") == "\x90\xC0");
static_assert(SmartcardController::ToBinary("90c1") == "\x90\xC1");
static_assert(SmartcardController::ToBinary("AB9C") == "\xAB\x9C");
static_assert(SmartcardController::ToBinary("ab9c") == "\xAB\x9C");

constexpr std::string SmartcardController::FromBinary(const std::string &binary) {
    std::string hex{};
    hex.resize(binary.size() * 2);
    auto iterator = hex.begin();
    for (const auto &input : binary) {
        auto ch = static_cast<unsigned char>(input);
        auto upper = ch >> 4;
        auto lower = ch & 0xF;
        *iterator = static_cast<char>(upper < 10 ? upper + '0' : upper + 'A' - 10);
        ++iterator;
        *iterator = static_cast<char>(lower < 10 ? lower + '0' : lower + 'A' - 10);
        ++iterator;
    }
    return hex;
}

static_assert(SmartcardController::FromBinary("") == "");
static_assert(SmartcardController::FromBinary("\x90") == "90");
static_assert(SmartcardController::FromBinary("\x90\xC0") == "90C0");
static_assert(SmartcardController::FromBinary("\x90\xC1") == "90C1");
static_assert(SmartcardController::FromBinary("\xAB\x9C") == "AB9C");
static_assert(SmartcardController::FromBinary(std::string("\xAB\x00\x9C", 3)) == "AB009C");
static_assert(SmartcardController::FromBinary(SmartcardController::ToBinary("AB009C")) == "AB009C");

using namespace std::chrono_literals;
static constexpr auto CONNECTION_TIMEOUT = 1min;

bool SmartcardController::is_connection_timed_out(const std::string &reader) {
    auto now = std::chrono::steady_clock::now();
    auto it = last_activity.find(reader);
    if (it == last_activity.end()) {
        return true;
    }
    auto elapsed = now - it->second;
    return elapsed > CONNECTION_TIMEOUT;
}

void SmartcardController::update_activity_timestamp(const std::string &reader) {
    last_activity.insert_or_assign(reader, std::chrono::steady_clock::now());
}

std::vector<std::string> SmartcardController::PinCmd(const std::string &scrambled) {
    std::string input{scrambled};
    input.erase(0, 4);
    if (input.size() < 4) {
        return {};
    }
    uint64_t ref{static_cast<uint64_t>(static_cast<unsigned char>(input[0]))};
    ref = ref << 8;
    ref |= static_cast<uint64_t>(static_cast<unsigned char>(input[1]));
    ref = ref << 8;
    ref |= static_cast<uint64_t>(static_cast<unsigned char>(input[2]));
    ref = ref << 8;
    ref |= static_cast<uint64_t>(static_cast<unsigned char>(input[3]));
    std::cout << "Pin ref " << ref << "\n";
    auto iterator = refs.find(ref);
    if (iterator == refs.end()) {
        return {};
    }
    auto key = iterator->second;
    // to not log the pin or key to deobfuscate pin
    // std::cout << "Key " << FromBinary(key) << "\n";
    input.erase(0, 4);
    if (input.size() < 2) {
        return {};
    }
    int cmdlen = static_cast<unsigned char>(input[0]);
    int pinlen = static_cast<unsigned char>(input[1]);
    input.erase(0, 2);
    if (input.size() < (cmdlen + pinlen)) {
        return {};
    }
    std::cout << "Cmd len " << cmdlen << ", pin len " << pinlen << "\n";
    if (key.size() < (pinlen * 2)) {
        return {};
    }
    for (decltype(input.size()) i = 0; i < pinlen; i++) {
        input[cmdlen + i] = input[cmdlen + i] ^ key[i] ^ key[pinlen + i];
    }
    return {input};
}

std::vector<std::string>
SmartcardController::RunApdu(const std::string &reader, const std::string &session, const std::vector<std::string> &commands) {
    std::vector<std::string> apdu{};
    apdu.reserve(commands.size());
    std::cout << "Reader " << reader << " session " << session << " requests:\n";
    for (const auto &cmd : commands) {
        if (cmd.starts_with("FFFF0104")) {
            // to not log the pin or key to deobfuscate pin
            // std::cout << "Reader " << reader << " session " << session << " request " << cmd << "\n";
            std::cout << "Reader " << reader << " session " << session << " request " << "FFFF0104**omitted**" << "\n";
            auto cmds = PinCmd(ToBinary(cmd));
            for (const auto &cmd : cmds) {
                // to not log the pin or key to deobfuscate pin
                // std::cout << "Reader " << reader << " session " << session << " pin request " << FromBinary(cmd) << "\n";
                std::cout << "Reader " << reader << " session " << session << " pin request " << "*omitted*" << "\n";
                apdu.emplace_back(cmd);
            }
        } else {
            std::cout << "Reader " << reader << " session " << session << " request " << cmd << "\n";
            apdu.emplace_back(ToBinary(cmd));
        }
    }
    std::cout << "Submitting:\n";
    std::shared_ptr<std::counting_semaphore<255>> product;
    {
        std::lock_guard lock{mtx};
        if (!TakeReader(reader, session)) {
            return {};
        }
        for (const auto &apducmd: apdu) {
            input[reader].emplace_back(apducmd);
            delivery[reader]->release();
        }
        product = this->product[reader];
    }
    for (auto &apducmd: apdu) {
        product->acquire();
        std::lock_guard lock{mtx};
        auto readerCheck = this->session.find(reader);
        if (readerCheck == this->session.end() || readerCheck->second != session){
            apducmd = "";
            continue;
        }
        auto bin = output[reader].begin();
        apducmd = FromBinary(*bin);
        bin = output[reader].erase(bin);
    }
    std::cout << "Reader " << reader << " session "<< session << "responses:\n";
    for (const auto &resp : apdu)  {
        std::cout << "Reader " << reader << " session "<< session << "response:" << resp << "\n";
    }
    return apdu;
}

void SmartcardController::Disconnect(const std::string &session) {
    std::cout << "Stop session " << session << "\n";
    {
        std::lock_guard lock{mtx};
        auto reader = GetReader(session);
        if (!reader) {
            return;
        }
        stop.emplace_back(*reader);
        delivery[*reader]->release();
    }
    std::cout << "Requested stop session " << session << "\n";
}

SmartcardKeyRef SmartcardController::GetRef() {
    std::cout << "Get ref\n";
    std::string data;
    data.resize(16);
    uint64_t ref;
    std::random_device rd;
    {
        std::uniform_int_distribution<int> dist(0, 255);
        for (char &d: data) {
            d = static_cast<char>(dist(rd) & 0xFF);
        }
    }
    {
        std::uniform_int_distribution<int> dist{0, 0x7FFFFFFF};
        ref = static_cast<uint64_t>(dist(rd) & 0x7FFFFFFF);
    }
    // to not log the pin or key to deobfuscate pin
    // std::cout << "Ref key " << ref << " " << FromBinary(data) << "\n";
    SmartcardKeyRef scRef{.key = FromBinary(data), .ref = ref};
    refs.insert_or_assign(ref, data);
    return scRef;
}