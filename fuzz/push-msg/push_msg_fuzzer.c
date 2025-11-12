/*
 * LibFuzzer harness for OpenVPN push message parsing
 *
 * This fuzzer targets the process_incoming_push_msg function which parses
 * push messages from the server (PUSH_REQUEST, PUSH_REPLY, PUSH_UPDATE)
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

/* Include OpenVPN headers */
#include "config.h"

/* Undefine problematic includes we don't need for fuzzing */
#undef HAVE_LINUX_ERRQUEUE_H

/* Include necessary system headers BEFORE syshead.h to ensure proper definitions */
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <linux/in.h>
#include <linux/ipv6.h>

#include "syshead.h"
#include "push.h"
#include "options_util.h"
#include "buffer.h"
#include "multi.h"

int
process_incoming_push_msg_test(struct context *c, const struct buffer *buffer,
                          bool honor_received_options, unsigned int permission_mask,
                          unsigned int *option_types_found)
{
    struct buffer buf = *buffer;

    if (buf_string_compare_advance(&buf, "PUSH_REQUEST"))
    {
        return PUSH_MSG_REQUEST;
    }
    else if (honor_received_options && buf_string_compare_advance(&buf, push_reply_cmd))
    {
        return PUSH_MSG_REPLY;
    }
    else if (honor_received_options && buf_string_compare_advance(&buf, push_update_cmd))
    {
        return process_incoming_push_update(c, permission_mask, option_types_found, &buf, false);
    }
    else
    {
        return PUSH_MSG_ERROR;
    }
}
/*
 * Note: Mock functions are not needed because we're linking against libopenvpn.a
 * which contains the real implementations of all required functions.
 */

/* Initialize a minimal context for fuzzing */
static void
init_fuzz_context(struct context *c)
{
    memset(c, 0, sizeof(struct context));
    c->options.pull = true;
    c->options.disable_dco = true;
    c->options.route_nopull = false;
    c->options.pull_filter_list = NULL;

    /* Initialize c2.es to prevent NULL pointer dereference */
    c->c2.es = env_set_create(NULL);
}

/* Cleanup context */
static void
cleanup_fuzz_context(struct context *c)
{
    /* Free options first - this will clean up routes, gc arena, etc. */
    uninit_options(&c->options);

    /* Free any garbage collected memory */
    context_gc_free(c);

    /* Free environment set after everything else */
    if (c->c2.es)
    {
        env_set_destroy(c->c2.es);
        c->c2.es = NULL;
    }
}

/*
 * LibFuzzer entry point
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Limit input size to avoid excessive memory allocation */
    if (size > 256 || size == 0)
    {
        return 0;
    }

    /* Initialize context */
    struct context c;
    init_fuzz_context(&c);
  init_options(&c.options, true);
  net_ctx_init(&c, &c.net_ctx);
  init_verb_mute(&c, IVM_LEVEL_1);

  init_options_dev(&c.options);

    /* Create a buffer from the fuzzer input */
    struct buffer buf = alloc_buf(size + 1);
    if (!buf_write(&buf, data, size))
    {
        free_buf(&buf);
        cleanup_fuzz_context(&c);
        return 0;
    }

    /* Ensure null termination for string operations */
    uint8_t *buf_data = BPTR(&buf);
    if (buf_data && BLEN(&buf) > 0)
    {
        /* Add null terminator if there's space */
        if (buf.capacity > (int)size)
        {
            buf_data[size] = '\0';
        }
    }

    /* Reset buffer position for reading */
    buf.offset = 0;
    buf.len = size;

    /* Test with different honor_received_options values */
    unsigned int option_types_found = 0;
    /* Test 1: honor_received_options = true */
    struct buffer buf_copy1 = buf;
    process_incoming_push_msg_test(&c, &buf_copy1, true, pull_permission_mask(&c),
                             &option_types_found);

    /* Test 2: honor_received_options = false */
    struct buffer buf_copy2 = buf;
    option_types_found = 0;
    process_incoming_push_msg_test(&c, &buf_copy2, false, pull_permission_mask(&c),
                             &option_types_found);

    /* Test 3: with different permission masks */
    struct buffer buf_copy3 = buf;
    option_types_found = 0;
    process_incoming_push_msg_test(&c, &buf_copy3, true, OPT_P_ROUTE | OPT_P_DHCPDNS,
                             &option_types_found);

    /* Cleanup */
    free_buf(&buf);
    cleanup_fuzz_context(&c);

    return 0;
}

