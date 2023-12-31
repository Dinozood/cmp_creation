//
// Created by dinozood on 31.12.23.
//

#ifndef CMP_CREATION_SESSION_H
#define CMP_CREATION_SESSION_H


#include <cstddef>
#include <vector>
#include <crypto-suites/crypto-bn/bn.h>
#include <iostream>
#include "Signer.h"
#include "thread_safe_queue.h"
#include "message.h"
#include "party_message_queue.h"


class Session {
public:
    Session(size_t _N = 3, size_t _T = 2);

    ~Session() = default;

    void set_workspace_id(std::string _id);

    void generate_shards();

    void sign_message(safeheron::bignum::BN msg);

    bool sign(Signer signer, safeheron::bignum::BN msg, std::vector<std::string> participants);

    void add_signer_to_current_operation(Signer *signer);

    void clear_current_session();

    bool key_gen(Signer signer, std::vector<std::string> remote_party_ids);

private:
    size_t N = 3;
    size_t T = 2;
    const size_t rounds_key_gen = 4;
    const size_t sign_rounds = 8;
    std::string workspace_id = "workspace 0";
    std::vector<Signer> signers;
    std::vector<Signer *> operation_signers;
    std::map<std::string, PartyMessageQue<Msg>> map_id_message_queue;
    safeheron::curve::CurveType curve_type = safeheron::curve::CurveType::SECP256K1;


};


#endif //CMP_CREATION_SESSION_H
