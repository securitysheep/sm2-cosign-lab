#ifndef RUNTIME_STATE_H
#define RUNTIME_STATE_H

#include "SM2_Multi_party_collaborative_signature.h"

extern Elliptic_Curve *g_curve;
extern User *g_users;
extern Server g_server;
extern Point g_group_key;
extern int g_user_count;
extern int g_has_group_key;

void reset_global_state(void);

#endif
