/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2026, by Timo Voelker. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * a) Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * b) Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the distribution.
 *
 * c) Neither the name of Cisco Systems, Inc. nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _NET_IF_OFFLOAD_H_
#define _NET_IF_OFFLOAD_H_

#include "opt_sctp.h"

/* required for if_private.h 
#include <sys/ck.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/altq/if_altq.h>
#include <net/if_private.h>
*/
struct ifnet;
struct mbuf;

#if defined(SCTP) || defined(SCTP_SUPPORT)
#define IF_OFFLOAD_EXPECTED4 (CSUM_IP | CSUM_IP_UDP | CSUM_IP_TCP | CSUM_IP_SCTP | CSUM_IP_PSEUDO | CSUM_IP_TSO)
#define IF_OFFLOAD_EXPECTED6 (CSUM_IP6_UDP | CSUM_IP6_TCP | CSUM_IP6_SCTP | CSUM_IP6_PSEUDO | CSUM_IP6_TSO)
#else
#define IF_OFFLOAD_EXPECTED4 (CSUM_IP | CSUM_IP_UDP | CSUM_IP_TCP | CSUM_IP_PSEUDO | CSUM_IP_TSO)
#define IF_OFFLOAD_EXPECTED6 (CSUM_IP6_UDP | CSUM_IP6_TCP | CSUM_IP6_PSEUDO | CSUM_IP6_TSO)
#endif /* defined(SCTP) || defined(SCTP_SUPPORT) */
#define IF_OFFLOAD_EXPECTED (IF_OFFLOAD_EXPECTED4 | IF_OFFLOAD_EXPECTED6)

int if_offload_transmit(struct ifnet *, struct mbuf *);

#endif /* !_NET_IF_OFFLOAD_H_ */
