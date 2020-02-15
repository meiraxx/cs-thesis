def calculate_talkers_features(flows, flow_ids):
    """Calculate and output talker features"""
    talker_ids = list()
    talkers = OrderedDict()
    for flow_id in flow_ids:
        curr_flow = flows[flow_id]
        src_ip = flow_id[0]
        dst_ip = flow_id[2]

        talker_id = (src_ip, dst_ip)

        # start and end times
        flow_start_time = curr_flow["flow_start_time"]
        flow_end_time = curr_flow["flow_end_time"]
        flow_duration = curr_flow["flow_duration"]

        try:
            talkers[talker_id][flow_id] = \
            {
                "flow_start_time": flow_start_time,
                "flow_end_time": flow_end_time,
                "flow_duration": flow_duration,
            }
        except KeyError:
            # talker_ids mantain the same order as flow_ids
            talker_ids.append(talker_id)
            talkers[talker_id] = OrderedDict()
            talkers[talker_id][flow_id] = \
            {
                "flow_start_time": flow_start_time,
                "flow_end_time": flow_end_time,
                "flow_duration": flow_duration,
            }


    for i, talker_id in enumerate(talker_ids):
        bwd_talker_id = (talker_id[1], talker_id[0])

        n_fwd_flows = len(talkers[talker_id])

        try:
            n_bwd_flows = len(talkers[bwd_talker_id])
        except KeyError:
            n_bwd_flows = 0

        #print("Talker %s ::: %s ::: %s" %(i,talker_id,talkers[talker_id]))

        # all flow durations of current talker
        flow_durations = []
        # first timestamps from forward and backward initiated talkers
        talker_first_times = []
        # last timestamps from forward and backward initiated talkers
        talker_last_times = []

        # FORWARDS
        for i, flow_id in enumerate(talkers[talker_id]):
            # flow durations
            curr_flow_duration = talkers[talker_id][flow_id]["flow_duration"]
            flow_durations.append(curr_flow_duration)
            # talker times
            # first flow
            if i==0:
                first_fwd_flow_start_time = talkers[talker_id][flow_id]["flow_start_time"]
                talker_first_times.append(first_fwd_flow_start_time)
            # last flow
            if i==n_fwd_flows-1:
                last_fwd_flow_start_time = talkers[talker_id][flow_id]["flow_end_time"]
                talker_last_times.append(last_fwd_flow_start_time)

        # BACKWARDS
        if bwd_talker_id in talkers:
            for i, flow_id in enumerate(talkers[bwd_talker_id]):
                # flow durations
                curr_flow_duration = talkers[bwd_talker_id][flow_id]["flow_duration"]
                flow_durations.append(curr_flow_duration)
                # talker times
                # first flow
                if i==0:
                    first_bwd_flow_start_time = talkers[bwd_talker_id][flow_id]["flow_start_time"]
                    talker_first_times.append(first_bwd_flow_start_time)
                # last flow
                if i==n_bwd_flows-1:
                    last_bwd_flow_start_time = talkers[bwd_talker_id][flow_id]["flow_end_time"]
                    talker_last_times.append(last_bwd_flow_start_time)

        talker_start_time = float(np.max(talker_first_times))
        talker_end_time = float(np.max(talker_last_times))
        talker_duration = talker_end_time - talker_start_time

        total_flow_duration = float(np.sum(flow_durations))
        mean_flow_duration = float(np.mean(flow_durations))
        std_flow_duration = float(np.std(flow_durations))
        var_flow_duration = float(np.var(flow_durations))
        max_flow_duration = float(np.max(flow_durations))
        min_flow_duration = float(np.min(flow_durations))

        fwd_flows_rate = 0 if total_flow_duration==0 else float(n_fwd_flows/total_flow_duration)
        bwd_flows_rate = 0 if total_flow_duration==0 else float(n_bwd_flows/total_flow_duration)

        talker_features_header = "talker_id,talker_start_time,talker_end_time,talker_duration,n_fwd_flows,n_bwd_flows,fwd_flows_rate,bwd_flows_rate," +\
        "total_flow_duration,mean_flow_duration,std_flow_duration,var_flow_duration,max_flow_duration,min_flow_duration," +\
        "label"
        talker_keys = talker_features_header.split(",")
        talker_values = \
            [talker_id, talker_start_time, talker_end_time, talker_duration, n_fwd_flows, n_bwd_flows, fwd_flows_rate, bwd_flows_rate,\
            total_flow_duration, mean_flow_duration, std_flow_duration, var_flow_duration, max_flow_duration, min_flow_duration,\
            args.label]

        talker_features_generator = dict(zip(talker_keys, talker_values))
        
        yield talker_features_generator


# Calculate Talker features
talker_features_generator = calculate_talkers_features(flows, flow_ids)
# PARSE Flows to create Talkers
talkers = OrderedDict()
for i, talker_features_dict in enumerate(talker_features_generator):
    curr_talker_id = talker_features_dict["talker_id"]
    talker_features_dict.pop(curr_talker_id, None)
    talkers[curr_talker_id] = talker_features_dict