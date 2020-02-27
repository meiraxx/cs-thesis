def calculate_talkers_features(biflows, biflow_ids):
    """Calculate and output talker features"""
    talker_ids = list()
    talkers = OrderedDict()
    for biflow_id in biflow_ids:
        curr_biflow = biflows[biflow_id]
        src_ip = biflow_id[0]
        dst_ip = biflow_id[2]

        talker_id = (src_ip, dst_ip)

        # start and end times
        biflow_start_time = curr_biflow["biflow_start_time"]
        biflow_end_time = curr_biflow["biflow_end_time"]
        biflow_duration = curr_biflow["biflow_duration"]

        try:
            talkers[talker_id][biflow_id] = \
            {
                "biflow_start_time": biflow_start_time,
                "biflow_end_time": biflow_end_time,
                "biflow_duration": biflow_duration,
            }
        except KeyError:
            # talker_ids mantain the same order as biflow_ids
            talker_ids.append(talker_id)
            talkers[talker_id] = OrderedDict()
            talkers[talker_id][biflow_id] = \
            {
                "biflow_start_time": biflow_start_time,
                "biflow_end_time": biflow_end_time,
                "biflow_duration": biflow_duration,
            }


    for i, talker_id in enumerate(talker_ids):
        bwd_talker_id = (talker_id[1], talker_id[0])

        n_fwd_biflows = len(talkers[talker_id])

        try:
            n_bwd_biflows = len(talkers[bwd_talker_id])
        except KeyError:
            n_bwd_biflows = 0

        #print("Talker %s ::: %s ::: %s" %(i,talker_id,talkers[talker_id]))

        # all biflow durations of current talker
        biflow_durations = []
        # first timestamps from forward and backward initiated talkers
        talker_first_times = []
        # last timestamps from forward and backward initiated talkers
        talker_last_times = []

        # FORWARDS
        for i, biflow_id in enumerate(talkers[talker_id]):
            # biflow durations
            curr_biflow_duration = talkers[talker_id][biflow_id]["biflow_duration"]
            biflow_durations.append(curr_biflow_duration)
            # talker times
            # first biflow
            if i==0:
                first_fwd_biflow_start_time = talkers[talker_id][biflow_id]["biflow_start_time"]
                talker_first_times.append(first_fwd_biflow_start_time)
            # last biflow
            if i==n_fwd_biflows-1:
                last_fwd_biflow_start_time = talkers[talker_id][biflow_id]["biflow_end_time"]
                talker_last_times.append(last_fwd_biflow_start_time)

        # BACKWARDS
        if bwd_talker_id in talkers:
            for i, biflow_id in enumerate(talkers[bwd_talker_id]):
                # biflow durations
                curr_biflow_duration = talkers[bwd_talker_id][biflow_id]["biflow_duration"]
                biflow_durations.append(curr_biflow_duration)
                # talker times
                # first biflow
                if i==0:
                    first_bwd_biflow_start_time = talkers[bwd_talker_id][biflow_id]["biflow_start_time"]
                    talker_first_times.append(first_bwd_biflow_start_time)
                # last biflow
                if i==n_bwd_biflows-1:
                    last_bwd_biflow_start_time = talkers[bwd_talker_id][biflow_id]["biflow_end_time"]
                    talker_last_times.append(last_bwd_biflow_start_time)

        talker_start_time = float(np.max(talker_first_times))
        talker_end_time = float(np.max(talker_last_times))
        talker_duration = talker_end_time - talker_start_time

        total_biflow_duration = float(np.sum(biflow_durations))
        mean_biflow_duration = float(np.mean(biflow_durations))
        std_biflow_duration = float(np.std(biflow_durations))
        var_biflow_duration = float(np.var(biflow_durations))
        max_biflow_duration = float(np.max(biflow_durations))
        min_biflow_duration = float(np.min(biflow_durations))

        fwd_biflows_rate = 0 if total_biflow_duration==0 else float(n_fwd_biflows/total_biflow_duration)
        bwd_biflows_rate = 0 if total_biflow_duration==0 else float(n_bwd_biflows/total_biflow_duration)

        talker_features_header = "talker_id,talker_start_time,talker_end_time,talker_duration,n_fwd_biflows,n_bwd_biflows,fwd_biflows_rate,bwd_biflows_rate," +\
        "total_biflow_duration,mean_biflow_duration,std_biflow_duration,var_biflow_duration,max_biflow_duration,min_biflow_duration," +\
        "label"
        talker_keys = talker_features_header.split(",")
        talker_values = \
            [talker_id, talker_start_time, talker_end_time, talker_duration, n_fwd_biflows, n_bwd_biflows, fwd_biflows_rate, bwd_biflows_rate,\
            total_biflow_duration, mean_biflow_duration, std_biflow_duration, var_biflow_duration, max_biflow_duration, min_biflow_duration,\
            args.label]

        talker_features_generator = dict(zip(talker_keys, talker_values))
        
        yield talker_features_generator


# Calculate Talker features
talker_features_generator = calculate_talkers_features(biflows, biflow_ids)
# PARSE Flows to create Talkers
talkers = OrderedDict()
for i, talker_features_dict in enumerate(talker_features_generator):
    curr_talker_id = talker_features_dict["talker_id"]
    talker_features_dict.pop(curr_talker_id, None)
    talkers[curr_talker_id] = talker_features_dict