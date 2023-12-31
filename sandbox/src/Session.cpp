//
// Created by dinozood on 31.12.23.
//

#include <multi-party-ecdsa/gg18/key_gen/context.h>

#include <utility>
#include <future>
#include <gtest/gtest.h>
#include "Session.h"


bool Session::key_gen(Signer signer, std::vector<std::string> remote_party_ids) {
    bool ok = true;
    std::string status;

    //create context (define in gg18/key_gen/context.h)
    ok = signer.set_context(N, curve_type, this->workspace_id, T, remote_party_ids);
    if (!ok) return false;

//        status = "<== Context of " + party_id + " was created\n";
//        printf("%s", status.c_str());

    //perform 3 rounds of MPC
    for (int round = 0; round < rounds_key_gen; ++round) {
        if (round == 0) {
            ok = signer.push_message();
            if (!ok) {
                signer.print_context_stack_if_failed();
                return false;
            }
        } else {
            for (int k = 0; k < N - 1; k++) {
                Msg m;
                ThreadSafeQueue<Msg> &in_queue = map_id_message_queue.at(signer.get_context_local_party_id()).get(
                        round - 1);
                in_queue.Pop(m);
                ok = signer.push_message(m.p2p_msg_, m.bc_msg_, m.src_, round - 1);
                if (!ok) {
                    signer.print_context_stack_if_failed();
                    return false;
                }
            }
        }

        ok = signer.finish_curr_round();
        if (!ok) {
            signer.print_context_stack_if_failed();
            return false;
        }

        std::string out_bc_message;
        std::vector <std::string> out_p2p_message_arr;
        std::vector <std::string> out_des_arr;
        ok = signer.pop_msgs(out_p2p_message_arr, out_bc_message, out_des_arr);
        if (!ok) {
            signer.print_context_stack_if_failed();
            return false;
        }

        for (size_t j = 0; j < out_des_arr.size(); ++j) {
            Msg m = {signer.get_context_local_party_id(), out_bc_message,
                     out_p2p_message_arr.empty() ? "" : out_p2p_message_arr[j]};
            ThreadSafeQueue<Msg> &out_queue = map_id_message_queue.at(out_des_arr[j]).get(round);
            out_queue.Push(m);
        }
    }

    ok = signer.finish();
    if (!ok) {
        signer.print_context_stack_if_failed();
        return false;
    }
    return true;
}


void Session::generate_shards() {
    std::future<bool> res[this->N];
    for (int i = 0; i < N; ++i) {
        signers.emplace_back(safeheron::bignum::BN(i + 1), "co_signer" + std::to_string(i + 1));
    }
    for (auto signer: signers) {
        map_id_message_queue[signer.get_name()] = PartyMessageQue<Msg>(this->rounds_key_gen);
    }
    for (int i = 0; i < signers.size(); ++i) {
        std::vector<std::string> remote_party_ids;
        for (auto other_signer: this->signers) {
            if (signers[i].get_id() != other_signer.get_id()) {
                remote_party_ids.push_back(other_signer.get_name());
            }
        }
        res[i] = std::async(std::launch::async, &Session::key_gen, this, signers[i], remote_party_ids);
    }
    for (int i = 0; i < N; ++i) {
        if (!res[i].get()) {
            std::cerr << "Error while key shards generation in " << i + 1 << "co_signer";
            exit(-1);
        }
    }
    map_id_message_queue.clear();
}

Session::Session(size_t _N, size_t _T) : T(_T), N(_N) {
    if (N < 2 or T < (2 * N / 3)) {
        std::cerr << "Invalid N or T params... sets to default t-n(2-3)\n";
    }
}

void Session::set_workspace_id(std::string _id) {
    workspace_id = std::move(_id);
}

void Session::sign_message(safeheron::bignum::BN msg) {
    std::vector<std::future<bool> >res;
    if (operation_signers.size() < T) {
        std::cerr << "Not enough participants for sign\n";
        clear_current_session();
    }
    res.resize(operation_signers.size());
    for (int i = 0; i < N; ++i) {
        map_id_message_queue[signers[i].get_name()] = PartyMessageQue<Msg>(sign_rounds);
    }

    std::vector<std::string> participants;
    for (auto signer : operation_signers) {
        participants.emplace_back(signer->get_name());
    }
    for (size_t i = 0; i < operation_signers.size(); ++i) {
        res[i] = std::async(std::launch::async, &Session::sign, this, *operation_signers[i], msg, participants);
    }

    for (size_t i = 0; i < operation_signers.size(); ++i) {
        if (!res[i].get()) {
            std::cerr << "Error while signing in " << i + 1 << "co_signer";
            exit(-1);
        }
    }

    map_id_message_queue.clear();
}

bool Session::sign(Signer signer, safeheron::bignum::BN msg, std::vector<std::string> participants) {
    bool ok = true;
//    just as
    ok = signer.create_sign_ctx(participants);
    if (!ok)
        return false;


    return ok;
}

void Session::clear_current_session() {
//    TODO: need to realise
}
