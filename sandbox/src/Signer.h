#ifndef CMP_CREATION_SIGNER_H
#define CMP_CREATION_SIGNER_H

#include <crypto-suites/crypto-bn/bn.h>
#include <multi-party-ecdsa/gg20/sign/context.h>

class Signer {
public:
    explicit Signer(safeheron::bignum::BN _id, std::string _name);

    ~Signer() = default;

    bool push_message();

    void print_context_stack_if_failed();

    std::string get_context_local_party_id();

    std::string get_name();

    safeheron::bignum::BN get_id();

    bool set_context(int _N, safeheron::curve::CurveType curveType, std::string workspace_id, int _T,
                     std::vector<std::string> remote_party_ids);

    bool set_context(int _N, std::string trim_key, safeheron::bignum::BN msg);

    bool push_message(std::string p2p, std::string bc, std::string src, int i);

    bool finish_curr_round();

    bool pop_msgs(std::vector<std::string> p2p_msg_arr, std::string out_bc_msg, std::vector<std::string> out_des_arr);

    bool finish();

    bool get_b64key(std::string &res);

    bool get_b64trim_key(std::string &res, std::vector<std::string> partips);

    bool get_json_key(std::string &res);

    bool create_sign_ctx(std::vector<std::string> &partips);

private:
    std::string name;
    safeheron::bignum::BN id;
    safeheron::multi_party_ecdsa::gg18::key_gen::Context ctx =
            safeheron::multi_party_ecdsa::gg18::key_gen::Context(0);
    safeheron::multi_party_ecdsa::gg20::sign::Context sign_cxt = safeheron::multi_party_ecdsa::gg20::sign::Context(0);

};


#endif //CMP_CREATION_SIGNER_H
