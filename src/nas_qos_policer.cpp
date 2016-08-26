
/*
 * Copyright (c) 2016 Dell Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * THIS CODE IS PROVIDED ON AN *AS IS* BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT
 * LIMITATION ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS
 * FOR A PARTICULAR PURPOSE, MERCHANTABLITY OR NON-INFRINGEMENT.
 *
 * See the Apache Version 2.0 License for specific language governing
 * permissions and limitations under the License.
 */


/*!
 * \file   nas_qos_policer.cpp
 * \brief  NAS QOS Policer Object
 * \date   02-2015
 * \author
 */

#include "event_log.h"
#include "std_assert.h"
#include "nas_qos_common.h"
#include "nas_qos_policer.h"
#include "dell-base-qos.h"
#include "nas_ndi_qos.h"
#include "nas_base_obj.h"
#include "nas_qos_switch.h"
#include <inttypes.h>

nas_qos_policer::nas_qos_policer (nas_qos_switch* switch_p)
           : base_obj_t (switch_p)
{
    memset(&cfg, 0, sizeof(cfg));
}

const nas_qos_switch& nas_qos_policer::get_switch()
{
    return static_cast<const nas_qos_switch&> (base_obj_t::get_switch());
}

bool  nas_qos_policer::opaque_data_to_cps (cps_api_object_t cps_obj) const
{
    constexpr size_t  attr_size = 1;
    cps_api_attr_id_t  attr_id_list[] = {BASE_QOS_METER_DATA};
    return nas::ndi_obj_id_table_cps_serialize (_ndi_obj_ids, cps_obj, attr_id_list, attr_size);
}

void nas_qos_policer::commit_create (bool rolling_back)

{
    if (!is_attr_dirty (BASE_QOS_METER_TYPE)) {
        throw nas::base_exception {NAS_BASE_E_CREATE_ONLY,
                        __PRETTY_FUNCTION__,
                        "Mandatory attribute Meter Type not present"};
    }

    base_obj_t::commit_create(rolling_back);
}

void* nas_qos_policer::alloc_fill_ndi_obj (nas::mem_alloc_helper_t& m)
{
    // NAS Qos policer does not allocate memory to save the incoming tentative attributes
    return this;
}

bool nas_qos_policer::push_create_obj_to_npu (npu_id_t npu_id,
                                     void* ndi_obj)
{
    ndi_obj_id_t ndi_policer_id;
    t_std_error rc;

    EV_LOG_TRACE(ev_log_t_QOS, 3, "NAS-QOS", "Creating obj on NPU %d", npu_id);

    nas_qos_policer * nas_qos_policer_p = static_cast<nas_qos_policer*> (ndi_obj);

    // form attr_list
    std::vector<uint64_t> attr_list;
    attr_list.resize(_set_attributes.len());


    uint_t num_attr = 0;
    for (auto attr_id: _set_attributes) {
        attr_list[num_attr++] = attr_id;
    }

    if ((rc = ndi_qos_create_policer (npu_id,
                                      &attr_list[0],
                                      num_attr,
                                      &nas_qos_policer_p->cfg.ndi_cfg,
                                      &ndi_policer_id))
            != STD_ERR_OK)
    {
        throw nas::base_exception {rc, __PRETTY_FUNCTION__,
            "NDI QoS Policer Create Failed"};
    }

    EV_LOG_TRACE(ev_log_t_QOS, 3, "NAS-QOS",
                 "Successfully created obj on NPU %d NDI ID %" PRIx64,
                 npu_id, ndi_policer_id);
    // Cache the new Policer ID generated by NDI
    _ndi_obj_ids[npu_id] = ndi_policer_id;

    return true;

}


bool nas_qos_policer::push_delete_obj_to_npu (npu_id_t npu_id)
{
    t_std_error rc;

    EV_LOG_TRACE(ev_log_t_QOS, 3, "NAS-QOS", "Deleting obj on NPU %d", npu_id);

    if ((rc = ndi_qos_delete_policer(npu_id, _ndi_obj_ids.at(npu_id)))
        != STD_ERR_OK)
    {
        throw nas::base_exception {rc, __PRETTY_FUNCTION__,
            "NDI Policer Delete Failed"};
    }

    return true;
}

bool nas_qos_policer::is_leaf_attr (nas_attr_id_t attr_id)
{
    // Table of function pointers to handle modify of Qos policer
    // attributes.
    static const std::unordered_map <BASE_QOS_METER_t,
                                     bool,
                                     std::hash<int>>
        _leaf_attr_map =
    {
        // modifiable objects
        {BASE_QOS_METER_MODE,             true},
        {BASE_QOS_METER_COLOR_SOURCE,    true},
        {BASE_QOS_METER_GREEN_PACKET_ACTION,true},
        {BASE_QOS_METER_YELLOW_PACKET_ACTION,true},
        {BASE_QOS_METER_RED_PACKET_ACTION,    true},
        {BASE_QOS_METER_COMMITTED_BURST,        true},
        {BASE_QOS_METER_COMMITTED_RATE,        true},
        {BASE_QOS_METER_PEAK_BURST,            true},
        {BASE_QOS_METER_PEAK_RATE ,            true},
        {BASE_QOS_METER_STAT_LIST ,            true},
        {BASE_QOS_METER_NPU_ID_LIST,            true},

        //The NPU ID list attribute is handled by the base object itself.
    };

    return (_leaf_attr_map.at(static_cast<BASE_QOS_METER_t>(attr_id)));
}

bool nas_qos_policer::push_leaf_attr_to_npu (nas_attr_id_t attr_id,
                                           npu_id_t npu_id)
{
    t_std_error rc = STD_ERR_OK;

    EV_LOG_TRACE(ev_log_t_QOS, 3, "QOS", "Modifying npu: %d, attr_id %d",
                    npu_id, attr_id);


    switch (attr_id) {
    case BASE_QOS_METER_MODE:
    case BASE_QOS_METER_COLOR_SOURCE:
    case BASE_QOS_METER_GREEN_PACKET_ACTION:
    case BASE_QOS_METER_YELLOW_PACKET_ACTION:
    case BASE_QOS_METER_RED_PACKET_ACTION:
    case BASE_QOS_METER_COMMITTED_BURST:
    case BASE_QOS_METER_COMMITTED_RATE:
    case BASE_QOS_METER_PEAK_BURST:
    case BASE_QOS_METER_PEAK_RATE:
    case BASE_QOS_METER_STAT_LIST:
        if ((rc = ndi_qos_set_policer_attr(npu_id, _ndi_obj_ids.at(npu_id),
                                           (BASE_QOS_METER_t)attr_id,
                                           &cfg.ndi_cfg))
                != STD_ERR_OK)
            {
                throw nas::base_exception {rc, __PRETTY_FUNCTION__,
                    "NDI attribute Set Failed"};
            }
        break;

    case BASE_QOS_METER_NPU_ID_LIST:
        // handled separately, not here
        break;

    default:
            STD_ASSERT (0); //non-modifiable object
    }

    return true;
}

void nas_qos_policer::poll_stats(policer_stats_struct_t &stats)
{
    BASE_QOS_POLICER_STAT_TYPE_t stat_list[] = {
          BASE_QOS_POLICER_STAT_TYPE_PACKETS,
          BASE_QOS_POLICER_STAT_TYPE_BYTES,
          BASE_QOS_POLICER_STAT_TYPE_GREEN_PACKETS,
          BASE_QOS_POLICER_STAT_TYPE_GREEN_BYTES,
          BASE_QOS_POLICER_STAT_TYPE_YELLOW_PACKETS,
          BASE_QOS_POLICER_STAT_TYPE_YELLOW_BYTES,
          BASE_QOS_POLICER_STAT_TYPE_RED_PACKETS,
          BASE_QOS_POLICER_STAT_TYPE_RED_BYTES
    };

    for (auto npu_id: npu_list()) {
        policer_stats_struct_t s = {0};
        ndi_obj_id_t ndi_policer_id = _ndi_obj_ids.at(npu_id);

        if (ndi_qos_get_policer_stat(npu_id, ndi_policer_id,
                sizeof(stat_list), stat_list, &s) == STD_ERR_OK) {
            stats.bytes += s.bytes;
            stats.packets += s.packets;
            stats.green_bytes += s.green_bytes;
            stats.green_packets += s.green_packets;
            stats.yellow_bytes += s.yellow_bytes;
            stats.yellow_packets += s.yellow_packets;
            stats.red_bytes += s.red_bytes;
            stats.red_packets += s.red_packets;
        }

    }

}
