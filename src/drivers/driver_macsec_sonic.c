/*
 * Driver interaction with Linux MACsec kernel module
 * Copyright (c) 2016, Sabrina Dubroca <sd@queasysnail.net> and Red Hat, Inc.
 * Copyright (c) 2019, The Linux Foundation
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"

#include <stdarg.h>

#include <openssl/aes.h>

#include "utils/common.h"
#include "driver.h"
#include "driver_wired_common.h"
#include "sonic_operators.h"

#define DRV_PREFIX "macsec_sonic"

#define LOG_FORMAT(FORMAT, ...) \
    DRV_PREFIX"(%s) : %s "FORMAT"\n",drv->ifname,__PRETTY_FUNCTION__,__VA_ARGS__

#define WPA_PRINT_LOG(FORMAT, ...) \
    wpa_printf(MSG_DEBUG, LOG_FORMAT(FORMAT, __VA_ARGS__))

#define PRINT_LOG(FORMAT, ...) \
    WPA_PRINT_LOG(FORMAT, __VA_ARGS__);

#define ENTER_LOG \
    PRINT_LOG("%s", "")

#define PAIR_EMPTY NULL,0
#define PAIR_ARRAY(pairs) pairs,(sizeof(pairs)/sizeof(*pairs))

#define DEFAULT_KEY_SEPARATOR  ":"
#define APP_DB_SEPARATOR       DEFAULT_KEY_SEPARATOR
#define STATE_DB_SEPARATOR     "|"

static char * create_buffer(const char * fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    unsigned int length = vsnprintf(NULL, 0, fmt, args) + 1;
    va_end(args);
    if (length < 1)
    {
        return NULL;
    }
    char * buffer = (char *)malloc(length);
    if (buffer == NULL)
    {
        return NULL;
    }
    va_start(args, fmt);
    vsnprintf(buffer, length, fmt, args);
    va_end(args);
    return buffer;
}

#define CREATE_SC_KEY(IFNAME, SC, SEPARATOR)    \
    create_buffer(                              \
        "%s"                                    \
        SEPARATOR "%" PRIu64 "",                \
        IFNAME,                                 \
        mka_sci_u64(&SC->sci))

#define CREATE_SA_KEY(IFNAME, SA, SEPARATOR)    \
    create_buffer(                              \
        "%s"                                    \
        SEPARATOR "%" PRIu64 ""                 \
        SEPARATOR "%u",                         \
        IFNAME,                                 \
        mka_sci_u64(&SA->sc->sci),              \
        (unsigned int)(SA->an))

static char * create_binary_hex(const void * binary, unsigned long long length)
{
    if (binary == NULL || length == 0)
    {
        return NULL;
    }
    char * buffer = (char *)malloc(2 * length + 1);
    if (buffer == NULL)
    {
        return NULL;
    }
    const unsigned char * input = (const unsigned char *)binary;
    for (unsigned long long i = 0; i < length; i++)
    {
        snprintf(&buffer[i * 2], 3, "%02X", input[i]);
    }
    return buffer;
}

static char *create_auth_key(const unsigned char *key, unsigned long long key_length)
{
    unsigned char buffer[16] = {0};
    AES_KEY aes;
    if (AES_set_encrypt_key(key, key_length * 8, &aes) < 0)
    {
        return NULL;
    }
    AES_ecb_encrypt(buffer, buffer, &aes, AES_ENCRYPT);
    char *auth_key = create_binary_hex(buffer, sizeof(buffer));
    return auth_key;
}

struct macsec_sonic_data
{
    struct driver_wired_common_data common;

    const char * ifname;
    sonic_db_handle sonic_manager;
};

static void *macsec_sonic_wpa_init(void *ctx, const char *ifname)
{
    struct macsec_sonic_data *drv;

    drv = os_zalloc(sizeof(*drv));
    if (!drv)
        return NULL;

    if (driver_wired_init_common(&drv->common, ifname, ctx) < 0)
    {
        os_free(drv);
        return NULL;
    }

    drv->ifname = ifname;
    drv->sonic_manager = sonic_db_get_manager();

    ENTER_LOG;
    return drv;
}

static void macsec_sonic_wpa_deinit(void *priv)
{
    struct macsec_sonic_data *drv = priv;

    ENTER_LOG;

    driver_wired_deinit_common(&drv->common);
    os_free(drv);
}

static int macsec_sonic_macsec_init(void *priv, struct macsec_init_params *params)
{
    struct macsec_sonic_data *drv = priv;
    ENTER_LOG;

    const struct sonic_db_name_value_pair pairs[] = 
    {
        {"enable", "false"},
        {"cipher_suite" , "GCM-AES-128"}, // Default cipher suite
    };
    int ret = sonic_db_set(
        drv->sonic_manager,
        APPL_DB,
        APP_MACSEC_PORT_TABLE_NAME,
        drv->ifname,
        PAIR_ARRAY(pairs));
    if (ret == SONIC_DB_SUCCESS)
    {
        const struct sonic_db_name_value_pair pairs[] = 
        {
            {"state", "ok"}
        };
        ret = sonic_db_wait(
            drv->sonic_manager,
            STATE_DB,
            STATE_MACSEC_PORT_TABLE_NAME,
            SET_COMMAND,
            drv->ifname,
            PAIR_ARRAY(pairs));
    }
    return ret;
}

static int macsec_sonic_macsec_deinit(void *priv)
{
    struct macsec_sonic_data *drv = priv;
    ENTER_LOG;

    int ret = sonic_db_del(
        drv->sonic_manager,
        APPL_DB,
        APP_MACSEC_PORT_TABLE_NAME,
        drv->ifname);
    if (ret == SONIC_DB_SUCCESS)
    {
        ret = sonic_db_wait(
            drv->sonic_manager,
            STATE_DB,
            STATE_MACSEC_PORT_TABLE_NAME,
            DEL_COMMAND,
            drv->ifname,
            PAIR_EMPTY);
    }
    return ret;
}

static int macsec_sonic_get_capability(void *priv, enum macsec_cap *cap)
{
    struct macsec_sonic_data *drv = priv;

    ENTER_LOG;

    *cap = MACSEC_CAP_INTEG_AND_CONF;

    return 0;
}

/**
 * macsec_sonic_enable_protect_frames - Set protect frames status
 * @priv: Private driver interface data
 * @enabled: true = protect frames enabled
 *           false = protect frames disabled
 * Returns: 0 on success, -1 on failure (or if not supported)
 */
static int macsec_sonic_enable_protect_frames(void *priv, bool enabled)
{
    struct macsec_sonic_data *drv = priv;
    PRINT_LOG("%s", enabled ? "true" : "false");

    const struct sonic_db_name_value_pair pairs[] = 
    {
        {"enable_protect", enabled ? "true" : "false"}
    };
    return sonic_db_set(
        drv->sonic_manager,
        APPL_DB,
        APP_MACSEC_PORT_TABLE_NAME,
        drv->ifname,
        PAIR_ARRAY(pairs));
}

/**
 * macsec_sonic_enable_encrypt - Set protect frames status
 * @priv: Private driver interface data
 * @enabled: true = protect frames enabled
 *           false = protect frames disabled
 * Returns: 0 on success, -1 on failure (or if not supported)
 */
static int macsec_sonic_enable_encrypt(void *priv, bool enabled)
{
    struct macsec_sonic_data *drv = priv;
    PRINT_LOG("%s", enabled ? "true" : "false");

    const struct sonic_db_name_value_pair pairs[] = 
    {
        {"enable_encrypt", enabled ? "true" : "false"}
    };
    return sonic_db_set(
        drv->sonic_manager,
        APPL_DB,
        APP_MACSEC_PORT_TABLE_NAME,
        drv->ifname,
        PAIR_ARRAY(pairs));
}

/**
 * macsec_sonic_set_replay_protect - Set replay protect status and window size
 * @priv: Private driver interface data
 * @enabled: true = replay protect enabled
 *           false = replay protect disabled
 * @window: replay window size, valid only when replay protect enabled
 * Returns: 0 on success, -1 on failure (or if not supported)
 */
static int macsec_sonic_set_replay_protect(void *priv, bool enabled,
                                           u32 window)
{
    struct macsec_sonic_data *drv = priv;
    PRINT_LOG("%s %u", enabled ? "true" : "false", window);

    char * buffer = create_buffer("%u", window);
    const struct sonic_db_name_value_pair pairs[] = 
    {
        {"enable_replay_protect", enabled ? "true" : "false"},
        {"replay_window", buffer}
    };
    int ret = sonic_db_set(
        drv->sonic_manager,
        APPL_DB,
        APP_MACSEC_PORT_TABLE_NAME,
        drv->ifname,
        PAIR_ARRAY(pairs));
    free(buffer);

    return ret;
}

/**
 * macsec_sonic_set_current_cipher_suite - Set current cipher suite
 * @priv: Private driver interface data
 * @cs: EUI64 identifier
 * Returns: 0 on success, -1 on failure (or if not supported)
 */
static int macsec_sonic_set_current_cipher_suite(void *priv, u64 cs)
{
    struct macsec_sonic_data *drv = priv;

    const char * cipher_suite = NULL;
    if (cs == CS_ID_GCM_AES_128)
    {
        cipher_suite = "GCM-AES-128";
    }
    else if (cs == CS_ID_GCM_AES_256)
    {
        cipher_suite = "GCM-AES-256";
    }
    else if (cs == CS_ID_GCM_AES_XPN_128)
    {
        cipher_suite = "GCM-AES-XPN-128";
    }
    else if (cs == CS_ID_GCM_AES_XPN_256)
    {
        cipher_suite = "GCM-AES-XPN-256";
    }
    else
    {
        return SONIC_DB_FAIL;
    }
    PRINT_LOG("%s(%016" PRIx64 ")", cipher_suite, cs);

    const struct sonic_db_name_value_pair pairs[] = 
    {
        {"cipher_suite", cipher_suite},
    };
    return sonic_db_set(
        drv->sonic_manager,
        APPL_DB,
        APP_MACSEC_PORT_TABLE_NAME,
        drv->ifname,
        PAIR_ARRAY(pairs));
}

/**
 * macsec_sonic_enable_controlled_port - Set controlled port status
 * @priv: Private driver interface data
 * @enabled: true = controlled port enabled
 *           false = controlled port disabled
 * Returns: 0 on success, -1 on failure (or if not supported)
 */
static int macsec_sonic_enable_controlled_port(void *priv, bool enabled)
{
    struct macsec_sonic_data *drv = priv;
    PRINT_LOG("%s", enabled ? "true" : "false");

    const struct sonic_db_name_value_pair pairs[] = 
    {
        {"enable", enabled ? "true" : "false"}
    };
    return sonic_db_set(
        drv->sonic_manager,
        APPL_DB,
        APP_MACSEC_PORT_TABLE_NAME,
        drv->ifname,
        PAIR_ARRAY(pairs));
}

/**
 * macsec_sonic_get_receive_lowest_pn - Get receive lowest PN
 * @priv: Private driver interface data
 * @sa: secure association
 * Returns: 0 on success, -1 on failure (or if not supported)
 */
static int macsec_sonic_get_receive_lowest_pn(void *priv, struct receive_sa *sa)
{
    struct macsec_sonic_data *drv = priv;

    char * key = CREATE_SA_KEY(drv->ifname, sa, APP_DB_SEPARATOR);
    u64 pn = 1;
    int ret = sonic_db_get_counter(
        drv->sonic_manager,
        COUNTERS_TABLE,
        key,
        "SAI_MACSEC_SA_ATTR_CURRENT_XPN",
        &pn);
    PRINT_LOG("SA %s PN %" PRIu64 "", key, pn);
    if (ret == SONIC_DB_SUCCESS)
    {
        sa->lowest_pn = pn;
    }
    free(key);
    return ret;
}

/**
 * macsec_sonic_set_receive_lowest_pn - Set receive lowest PN
 * @priv: Private driver interface data
 * @sa: secure association
 * Returns: 0 on success, -1 on failure (or if not supported)
 */
static int macsec_sonic_set_receive_lowest_pn(void *priv, struct receive_sa *sa)
{
    struct macsec_sonic_data *drv = priv;

    char * key = CREATE_SA_KEY(drv->ifname, sa, APP_DB_SEPARATOR);
    PRINT_LOG("%s - %" PRIu64 "", key, sa->lowest_pn);
    char * buffer = create_buffer("%" PRIu64 "", sa->lowest_pn);
    const struct sonic_db_name_value_pair pairs[] = 
    {
        {"lowest_acceptable_pn", buffer}
    };
    int ret = sonic_db_set(
        drv->sonic_manager,
        APPL_DB,
        APP_MACSEC_INGRESS_SA_TABLE_NAME,
        key,
        PAIR_ARRAY(pairs));
    free(buffer);
    free(key);

    return ret;
}

/**
 * macsec_sonic_get_transmit_next_pn - Get transmit next PN
 * @priv: Private driver interface data
 * @sa: secure association
 * Returns: 0 on success, -1 on failure (or if not supported)
 */
static int macsec_sonic_get_transmit_next_pn(void *priv, struct transmit_sa *sa)
{
    struct macsec_sonic_data *drv = priv;

    char * key = CREATE_SA_KEY(drv->ifname, sa, APP_DB_SEPARATOR);
    u64 pn = 1;
    int ret = sonic_db_get_counter(
        drv->sonic_manager,
        COUNTERS_TABLE,
        key,
        "SAI_MACSEC_SA_ATTR_CURRENT_XPN",
        &pn);
    PRINT_LOG("SA %s PN %" PRIu64 "", key, pn);
    if (ret == SONIC_DB_SUCCESS)
    {
        sa->next_pn = pn;
    }
    free(key);

    return ret;
}

/**
 * macsec_sonic_set_transmit_next_pn - Set transmit next pn
 * @priv: Private driver interface data
 * @sa: secure association
 * Returns: 0 on success, -1 on failure (or if not supported)
 */
static int macsec_sonic_set_transmit_next_pn(void *priv, struct transmit_sa *sa)
{
    struct macsec_sonic_data *drv = priv;

    char * key = CREATE_SA_KEY(drv->ifname, sa, APP_DB_SEPARATOR);
    PRINT_LOG("%s - %" PRIu64 "", key, sa->next_pn);
    char * buffer = create_buffer("%" PRIu64 "", sa->next_pn);
    const struct sonic_db_name_value_pair pairs[] = 
    {
        {"next_pn", buffer}
    };
    int ret = sonic_db_set(
        drv->sonic_manager,
        APPL_DB,
        APP_MACSEC_EGRESS_SA_TABLE_NAME,
        key,
        PAIR_ARRAY(pairs));
    free(buffer);
    free(key);

    return ret;
}

#define SCISTR MACSTR "::%hx"
#define SCI2STR(addr, port) MAC2STR(addr), htons(port)

/**
 * macsec_sonic_create_receive_sc - Create secure channel for receiving
 * @priv: Private driver interface data
 * @sc: secure channel
 * @sci_addr: secure channel identifier - address
 * @sci_port: secure channel identifier - port
 * @conf_offset: confidentiality offset (0, 30, or 50)
 * @validation: frame validation policy (0 = Disabled, 1 = Checked,
 *	2 = Strict)
 * Returns: 0 on success, -1 on failure (or if not supported)
 */
static int macsec_sonic_create_receive_sc(void *priv, struct receive_sc *sc,
                                          unsigned int conf_offset,
                                          int validation)
{
    struct macsec_sonic_data *drv = priv;

    char * key = CREATE_SC_KEY(drv->ifname, sc, APP_DB_SEPARATOR);
    PRINT_LOG("%s (conf_offset=%u validation=%d)",
        key,
        conf_offset,
        validation);
    const struct sonic_db_name_value_pair pairs[] = 
    {
        {"Null", "Null"},
    };
    // TODO 
    // Validation
    // OFFSET
    int ret = sonic_db_set(
        drv->sonic_manager,
        APPL_DB,
        APP_MACSEC_INGRESS_SC_TABLE_NAME,
        key,
        PAIR_ARRAY(pairs));
    free(key);
    if (ret == SONIC_DB_SUCCESS)
    {
        const struct sonic_db_name_value_pair pairs[] = 
        {
            {"state", "ok"}
        };
        char * key = CREATE_SC_KEY(drv->ifname, sc, STATE_DB_SEPARATOR);
        ret = sonic_db_wait(
            drv->sonic_manager,
            STATE_DB,
            STATE_MACSEC_INGRESS_SC_TABLE_NAME,
            SET_COMMAND,
            key,
            PAIR_ARRAY(pairs));
        free(key);
    }

    return ret;
}

/**
 * macsec_sonic_delete_receive_sc - Delete secure connection for receiving
 * @priv: private driver interface data from init()
 * @sc: secure channel
 * Returns: 0 on success, -1 on failure
 */
static int macsec_sonic_delete_receive_sc(void *priv, struct receive_sc *sc)
{
    struct macsec_sonic_data *drv = priv;

    char * key = CREATE_SC_KEY(drv->ifname, sc, APP_DB_SEPARATOR);
    PRINT_LOG("%s", key);
    int ret = sonic_db_del(
        drv->sonic_manager,
        APPL_DB,
        APP_MACSEC_INGRESS_SC_TABLE_NAME,
        key);
    free(key);
    if (ret == SONIC_DB_SUCCESS)
    {
        char * key = CREATE_SC_KEY(drv->ifname, sc, STATE_DB_SEPARATOR);
        ret = sonic_db_wait(
            drv->sonic_manager,
            STATE_DB,
            STATE_MACSEC_INGRESS_SC_TABLE_NAME,
            DEL_COMMAND,
            key,
            PAIR_EMPTY);
        free(key);
    }

    return ret;
}

/**
 * macsec_sonic_create_receive_sa - Create secure association for receive
 * @priv: private driver interface data from init()
 * @sa: secure association
 * Returns: 0 on success, -1 on failure
 */
static int macsec_sonic_create_receive_sa(void *priv, struct receive_sa *sa)
{
    struct macsec_sonic_data *drv = priv;

    char * key = CREATE_SA_KEY(drv->ifname, sa, APP_DB_SEPARATOR);
    char * sak_id = create_binary_hex(&sa->pkey->key_identifier, sizeof(sa->pkey->key_identifier));
    char * sak = create_binary_hex(sa->pkey->key, sa->pkey->key_len);
    char * pn = create_buffer("%" PRIu64 "", sa->lowest_pn);
    char * auth_key = create_auth_key(sa->pkey->key, sa->pkey->key_len);
    char * ssci = create_buffer("%u", sa->sc->ssci);
    char * salt = create_binary_hex(&sa->pkey->salt, sizeof(sa->pkey->salt));
    PRINT_LOG("%s (enable_receive=%d next_pn=%" PRIu64 ") %s %s",
        key,
        sa->enable_receive,
        sa->lowest_pn,
        sak_id,
        sak);

    const struct sonic_db_name_value_pair pairs[] = 
    {
        {"active", "false"},
        {"sak", sak},
        {"auth_key", auth_key},
        {"lowest_acceptable_pn", pn},
        {"ssci", ssci},
        {"salt", salt}
    };
    int ret = sonic_db_set(
        drv->sonic_manager,
        APPL_DB,
        APP_MACSEC_INGRESS_SA_TABLE_NAME,
        key,
        PAIR_ARRAY(pairs));
    free(key);
    free(sak_id);
    free(sak);
    free(pn);
    free(auth_key);
    free(ssci);
    free(salt);
    return ret;
}

/**
 * macsec_sonic_delete_receive_sa - Delete secure association for receive
 * @priv: private driver interface data from init()
 * @sa: secure association
 * Returns: 0 on success, -1 on failure
 */
static int macsec_sonic_delete_receive_sa(void *priv, struct receive_sa *sa)
{
    struct macsec_sonic_data *drv = priv;

    char * key = CREATE_SA_KEY(drv->ifname, sa, APP_DB_SEPARATOR);
    PRINT_LOG("%s", key);
    int ret = sonic_db_del(
        drv->sonic_manager,
        APPL_DB,
        APP_MACSEC_INGRESS_SA_TABLE_NAME,
        key);
    free(key);
    if (ret == SONIC_DB_SUCCESS)
    {
        char * key = CREATE_SA_KEY(drv->ifname, sa, STATE_DB_SEPARATOR);
        ret = sonic_db_wait(
            drv->sonic_manager,
            STATE_DB,
            STATE_MACSEC_INGRESS_SA_TABLE_NAME,
            DEL_COMMAND,
            key,
            PAIR_EMPTY);
        free(key);
    }

    return ret;
}

/**
 * macsec_sonic_enable_receive_sa - Enable the SA for receive
 * @priv: private driver interface data from init()
 * @sa: secure association
 * Returns: 0 on success, -1 on failure
 */
static int macsec_sonic_enable_receive_sa(void *priv, struct receive_sa *sa)
{
    struct macsec_sonic_data *drv = priv;

    char * key = CREATE_SA_KEY(drv->ifname, sa, APP_DB_SEPARATOR);
    PRINT_LOG("%s", key);
    const struct sonic_db_name_value_pair pairs[] = 
    {
        {"active", "true"},
    };
    int ret = sonic_db_set(
        drv->sonic_manager,
        APPL_DB,
        APP_MACSEC_INGRESS_SA_TABLE_NAME,
        key,
        PAIR_ARRAY(pairs));
    free(key);
    if (ret == SONIC_DB_SUCCESS)
    {
        const struct sonic_db_name_value_pair pairs[] = 
        {
            {"state", "ok"},
        };
        char * key = CREATE_SA_KEY(drv->ifname, sa, STATE_DB_SEPARATOR);
        ret = sonic_db_wait(
            drv->sonic_manager,
            STATE_DB,
            STATE_MACSEC_INGRESS_SA_TABLE_NAME,
            SET_COMMAND,
            key,
            PAIR_ARRAY(pairs));
        free(key);
    }

    return ret;
}

/**
 * macsec_sonic_disable_receive_sa - Disable SA for receive
 * @priv: private driver interface data from init()
 * @sa: secure association
 * Returns: 0 on success, -1 on failure
 */
static int macsec_sonic_disable_receive_sa(void *priv, struct receive_sa *sa)
{
    struct macsec_sonic_data *drv = priv;

    char * key = CREATE_SA_KEY(drv->ifname, sa, APP_DB_SEPARATOR);
    PRINT_LOG("%s", key);
    const struct sonic_db_name_value_pair pairs[] = 
    {
        {"active", "false"},
    };
    int ret = sonic_db_set(
        drv->sonic_manager,
        APPL_DB,
        APP_MACSEC_INGRESS_SA_TABLE_NAME,
        key,
        PAIR_ARRAY(pairs));
    free(key);

    return ret;
}

/**
 * macsec_sonic_create_transmit_sc - Create secure connection for transmit
 * @priv: private driver interface data from init()
 * @sc: secure channel
 * @conf_offset: confidentiality offset
 * Returns: 0 on success, -1 on failure
 */
static int macsec_sonic_create_transmit_sc(
    void *priv, struct transmit_sc *sc,
    unsigned int conf_offset)
{
    struct macsec_sonic_data *drv = priv;

    char * key = CREATE_SC_KEY(drv->ifname, sc, APP_DB_SEPARATOR);
    PRINT_LOG("%s (conf_offset=%u)",
        key,
        conf_offset);
    // TODO 
    // Validation
    const struct sonic_db_name_value_pair pairs[] = 
    {
        {"encoding_an", "0"},
    };
    int ret = sonic_db_set(
        drv->sonic_manager,
        APPL_DB,
        APP_MACSEC_EGRESS_SC_TABLE_NAME,
        key,
        PAIR_ARRAY(pairs));
    free(key);
    if (ret == SONIC_DB_SUCCESS)
    {
        const struct sonic_db_name_value_pair pairs[] = 
        {
            {"state", "ok"},
        };
        char * key = CREATE_SC_KEY(drv->ifname, sc, STATE_DB_SEPARATOR);
        ret = sonic_db_wait(
            drv->sonic_manager,
            STATE_DB,
            STATE_MACSEC_EGRESS_SC_TABLE_NAME,
            SET_COMMAND,
            key,
            PAIR_ARRAY(pairs));
        free(key);
    }

    return ret;
}

/**
 * macsec_sonic_delete_transmit_sc - Delete secure connection for transmit
 * @priv: private driver interface data from init()
 * @sc: secure channel
 * Returns: 0 on success, -1 on failure
 */
static int macsec_sonic_delete_transmit_sc(void *priv, struct transmit_sc *sc)
{

    struct macsec_sonic_data *drv = priv;

    char * key = CREATE_SC_KEY(drv->ifname, sc, APP_DB_SEPARATOR);
    PRINT_LOG("%s", key);
    int ret = sonic_db_del(
        drv->sonic_manager,
        APPL_DB,
        APP_MACSEC_EGRESS_SC_TABLE_NAME,
        key);
    free(key);
    if (ret == SONIC_DB_SUCCESS)
    {
        char * key = CREATE_SC_KEY(drv->ifname, sc, STATE_DB_SEPARATOR);
        ret = sonic_db_wait(
            drv->sonic_manager,
            STATE_DB,
            STATE_MACSEC_EGRESS_SC_TABLE_NAME,
            DEL_COMMAND,
            key,
            PAIR_EMPTY);
        free(key);
    }

    return ret;
}

/**
 * macsec_sonic_create_transmit_sa - Create secure association for transmit
 * @priv: private driver interface data from init()
 * @sa: secure association
 * Returns: 0 on success, -1 on failure
 */
static int macsec_sonic_create_transmit_sa(void *priv, struct transmit_sa *sa)
{
    struct macsec_sonic_data *drv = priv;

    char * key = CREATE_SA_KEY(drv->ifname, sa, APP_DB_SEPARATOR);
    char * sak_id = create_binary_hex(&sa->pkey->key_identifier, sizeof(sa->pkey->key_identifier));
    char * sak = create_binary_hex(sa->pkey->key, sa->pkey->key_len);
    char * pn = create_buffer("%" PRIu64 "", sa->next_pn);
    char * auth_key = create_auth_key(sa->pkey->key, sa->pkey->key_len);
    char * ssci = create_buffer("%u", sa->sc->ssci);
    char * salt = create_binary_hex(&sa->pkey->salt, sizeof(sa->pkey->salt));
    PRINT_LOG("%s (enable_receive=%d next_pn=%" PRIu64 ") %s %s",
        key,
        sa->enable_transmit,
        sa->next_pn,
        sak_id,
        sak);

    const struct sonic_db_name_value_pair pairs[] = 
    {
        {"sak", sak},
        {"auth_key", auth_key},
        {"next_pn", pn},
        {"ssci", ssci},
        {"salt", salt}
    };
    int ret = sonic_db_set(
        drv->sonic_manager,
        APPL_DB,
        APP_MACSEC_EGRESS_SA_TABLE_NAME,
        key,
        PAIR_ARRAY(pairs));
    free(key);
    free(sak_id);
    free(sak);
    free(pn);
    free(auth_key);
    free(ssci);
    free(salt);

    return ret;
}

/**
 * macsec_sonic_delete_transmit_sa - Delete secure association for transmit
 * @priv: private driver interface data from init()
 * @sa: secure association
 * Returns: 0 on success, -1 on failure
 */
static int macsec_sonic_delete_transmit_sa(void *priv, struct transmit_sa *sa)
{
    struct macsec_sonic_data *drv = priv;

    char * key = CREATE_SA_KEY(drv->ifname, sa, APP_DB_SEPARATOR);
    PRINT_LOG("%s", key);
    int ret = sonic_db_del(
        drv->sonic_manager,
        APPL_DB,
        APP_MACSEC_EGRESS_SA_TABLE_NAME,
        key);
    free(key);
    if (ret == SONIC_DB_SUCCESS)
    {
        char * key = CREATE_SA_KEY(drv->ifname, sa, STATE_DB_SEPARATOR);
        ret = sonic_db_wait(
            drv->sonic_manager,
            STATE_DB,
            STATE_MACSEC_EGRESS_SA_TABLE_NAME,
            DEL_COMMAND,
            key,
            PAIR_EMPTY);
        free(key);
    }

    return ret;
}

/**
 * macsec_sonic_enable_transmit_sa - Enable SA for transmit
 * @priv: private driver interface data from init()
 * @sa: secure association
 * Returns: 0 on success, -1 on failure
 */
static int macsec_sonic_enable_transmit_sa(void *priv, struct transmit_sa *sa)
{
    struct macsec_sonic_data *drv = priv;

    char * key = CREATE_SC_KEY(drv->ifname, sa->sc, APP_DB_SEPARATOR);
    PRINT_LOG("%s", key);
    char * encoding_an = create_buffer("%u", sa->an);
    const struct sonic_db_name_value_pair pairs[] = 
    {
        {"encoding_an", encoding_an},
    };
    int ret = sonic_db_set(
        drv->sonic_manager,
        APPL_DB,
        APP_MACSEC_EGRESS_SC_TABLE_NAME,
        key,
        PAIR_ARRAY(pairs));
    free(key);
    if (ret == SONIC_DB_SUCCESS)
    {
        const struct sonic_db_name_value_pair pairs[] = 
        {
            {"state", "ok"},
        };
        char * key = CREATE_SA_KEY(drv->ifname, sa, STATE_DB_SEPARATOR);
        ret = sonic_db_wait(
            drv->sonic_manager,
            STATE_DB,
            STATE_MACSEC_EGRESS_SA_TABLE_NAME,
            SET_COMMAND,
            key,
            PAIR_ARRAY(pairs));
        free(key);
    }
    free(encoding_an);

    return ret;
}

/**
 * macsec_sonic_disable_transmit_sa - Disable SA for transmit
 * @priv: private driver interface data from init()
 * @sa: secure association
 * Returns: 0 on success, -1 on failure
 */
static int macsec_sonic_disable_transmit_sa(void *priv, struct transmit_sa *sa)
{
    struct macsec_sonic_data *drv = priv;

    char * key = CREATE_SA_KEY(drv->ifname, sa, APP_DB_SEPARATOR);
    PRINT_LOG("%s", key);
    free(key);

    return SONIC_DB_SUCCESS;
}

static int macsec_sonic_status(void *priv, char *buf, size_t buflen)
{
    struct macsec_sonic_data *drv = priv;
    int res;
    char *pos, *end;

    pos = buf;
    end = buf + buflen;

    res = os_snprintf(pos, end - pos,
                      "ifname=%s\n",
                      drv->ifname);
    if (os_snprintf_error(end - pos, res))
        return pos - buf;
    pos += res;

    return pos - buf;
}

const struct wpa_driver_ops wpa_driver_macsec_sonic_ops = {
    .name = "macsec_sonic",
    .desc = "MACsec Ethernet driver for SONiC",
    .get_ssid = driver_wired_get_ssid,
    .get_bssid = driver_wired_get_bssid,
    .get_capa = driver_wired_get_capa,
    .init = macsec_sonic_wpa_init,
    .deinit = macsec_sonic_wpa_deinit,

    .macsec_init = macsec_sonic_macsec_init,
    .macsec_deinit = macsec_sonic_macsec_deinit,
    .macsec_get_capability = macsec_sonic_get_capability,
    .enable_protect_frames = macsec_sonic_enable_protect_frames,
    .enable_encrypt = macsec_sonic_enable_encrypt,
    .set_replay_protect = macsec_sonic_set_replay_protect,
    .set_current_cipher_suite = macsec_sonic_set_current_cipher_suite,
    .enable_controlled_port = macsec_sonic_enable_controlled_port,
    .get_receive_lowest_pn = macsec_sonic_get_receive_lowest_pn,
    .set_receive_lowest_pn = macsec_sonic_set_receive_lowest_pn,
    .get_transmit_next_pn = macsec_sonic_get_transmit_next_pn,
    .set_transmit_next_pn = macsec_sonic_set_transmit_next_pn,
    .create_receive_sc = macsec_sonic_create_receive_sc,
    .delete_receive_sc = macsec_sonic_delete_receive_sc,
    .create_receive_sa = macsec_sonic_create_receive_sa,
    .delete_receive_sa = macsec_sonic_delete_receive_sa,
    .enable_receive_sa = macsec_sonic_enable_receive_sa,
    .disable_receive_sa = macsec_sonic_disable_receive_sa,
    .create_transmit_sc = macsec_sonic_create_transmit_sc,
    .delete_transmit_sc = macsec_sonic_delete_transmit_sc,
    .create_transmit_sa = macsec_sonic_create_transmit_sa,
    .delete_transmit_sa = macsec_sonic_delete_transmit_sa,
    .enable_transmit_sa = macsec_sonic_enable_transmit_sa,
    .disable_transmit_sa = macsec_sonic_disable_transmit_sa,

    .status = macsec_sonic_status,
};
