//
// Created by dinozood on 31.12.23.
//

#include "Signer.h"

#include <utility>

Signer::Signer(safeheron::bignum::BN _id, std::string _name) : id(std::move(_id)), name(std::move(_name)) {

}

void Signer::print_context_stack_if_failed() {
    std::string err_info;
    std::vector<safeheron::mpc_flow::mpc_parallel_v2::ErrorInfo> error_stack;
    ctx.get_error_stack(error_stack);
    for (const auto &err: error_stack) {
        err_info += "error code ( " + std::to_string(err.code_) + " ) : " + err.info_ + "\n";
    }
    printf("%s", err_info.c_str());
}

bool Signer::set_context(int _N, safeheron::curve::CurveType curveType, std::string workspace_id, int _T,
                         std::vector<std::string> remote_party_ids) {
    bool res = true;
    ctx = safeheron::multi_party_ecdsa::gg18::key_gen::Context(_N);
    res = safeheron::multi_party_ecdsa::gg18::key_gen::Context::CreateContext(ctx, curveType, workspace_id, _T,
                                                                              _N, this->name, this->id,
                                                                              remote_party_ids);

    return res;
}

bool Signer::push_message() {
    return ctx.PushMessage();
}

std::string Signer::get_context_local_party_id() {
    return ctx.sign_key_.local_party_.party_id_;
}

bool Signer::push_message(std::string p2p, std::string bc, std::string src, int i) {
    return ctx.PushMessage(p2p, bc, src, i);
}

bool Signer::finish_curr_round() {
    return ctx.IsCurRoundFinished();
}

bool
Signer::pop_msgs(std::vector<std::string> p2p_msg_arr, std::string out_bc_msg, std::vector<std::string> out_des_arr) {
    return ctx.PopMessages(p2p_msg_arr, out_bc_msg, out_des_arr);
}

bool Signer::finish() {
    return ctx.IsFinished();
}

bool Signer::get_b64key(std::string &res) {
    return ctx.sign_key_.ToBase64(res);;
}

bool Signer::get_b64trim_key(std::string &res, std::vector<std::string> partips) {
    std::string b64_key;
    bool result = get_b64key(b64_key);
    return safeheron::multi_party_ecdsa::gg18::trim_sign_key(b64_key, res, partips);
}

bool Signer::get_json_key(std::string &res) {
    return ctx.sign_key_.ToJsonString(res);
}

bool Signer::set_context(int _N, std::string trim_key, safeheron::bignum::BN msg) {
    sign_cxt = safeheron::multi_party_ecdsa::gg20::sign::Context(_N);
    return safeheron::multi_party_ecdsa::gg20::sign::Context::CreateContext(sign_cxt, trim_key, msg);
}

bool Signer::create_sign_ctx(std::vector<std::string> &partips) {
    return true;
}

std::string Signer::get_name() {
    return name;
}

safeheron::bignum::BN Signer::get_id() {
    return id;
}


