def calculate_hosts_features(talkers):
    """Calculate and output host features"""
    host_ids = list()
    hosts = OrderedDict()
    for talker_id in talkers:
        curr_talker = talkers[talker_id]
        src_ip = talker_id[0]
        dst_ip = talker_id[1]
        
        # start and end times
        #host_active_start_time = curr_talker["talker_start_time"]
        #host_active_end_time = curr_talker["talker_end_time"]
        talker_start_time = curr_talker["talker_start_time"]
        talker_end_time = curr_talker["talker_end_time"]
        talker_duration = curr_talker["talker_duration"]
        total_flow_duration = curr_talker["total_flow_duration"]

        # SOURCE
        try:
            hosts[src_ip][talker_id] = \
            {
                "talker_start_time": talker_start_time,
                "talker_end_time": talker_end_time,
                "talker_duration": talker_duration,
                "total_flow_duration": total_flow_duration,
            }
        except KeyError:
            host_ids.append(src_ip)
            hosts[src_ip] = OrderedDict()
            hosts[src_ip][talker_id] = \
            {
                "talker_start_time": talker_start_time,
                "talker_end_time": talker_end_time,
                "talker_duration": talker_duration,
                "total_flow_duration": total_flow_duration,
            }

        # DESTINATION
        try:
            hosts[dst_ip][talker_id] = \
            {
                "talker_start_time": talker_start_time,
                "talker_end_time": talker_end_time,
                "talker_duration": talker_duration,
                "total_flow_duration": total_flow_duration,
            }
        except KeyError:
            host_ids.append(dst_ip)
            hosts[dst_ip] = OrderedDict()
            hosts[dst_ip][talker_id] = \
            {
                "talker_start_time": talker_start_time,
                "talker_end_time": talker_end_time,
                "talker_duration": talker_duration,
                "total_flow_duration": total_flow_duration,
            }

    for i, host_id in enumerate(host_ids):
        n_talkers = len(hosts[host_id])
        rate_talkers = 0.01

        host_features_header = "host_id,n_talkers,rate_talkers,"+\
        "label"

        host_keys = host_features_header.split(",")
        host_values = \
            [host_id, n_talkers, rate_talkers,\
            args.label]

        host_features_generator = dict(zip(host_keys, host_values))
        
        yield host_features_generator


# CALCULATE Host features
host_features_generator = calculate_hosts_features(talkers)
# PARSE Talkers to create Hosts
hosts = OrderedDict()
for i, host_features_dict in enumerate(host_features_generator):
    curr_host_id = host_features_dict["host_id"]
    host_features_dict.pop(curr_host_id, None)
    hosts[curr_host_id] = host_features_dict