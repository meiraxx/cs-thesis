# TALKERS
talkerid_sqltalkerid = dict()
for talker_id in talkers:
    src_ip = talker_id[0]
    dst_ip = talker_id[1]

    # SQL Ids - Foreign Key Relations
    src_sql_host_id = hostid_sqlhostid[src_ip]
    dst_sql_host_id = hostid_sqlhostid[dst_ip]

    # talker features
    talker_start_time = talkers[talker_id]["talker_start_time"]
    talker_end_time = talkers[talker_id]["talker_end_time"]
    talker_duration = talkers[talker_id]["talker_duration"]
    n_fwd_flows = talkers[talker_id]["n_fwd_flows"]
    n_bwd_flows = talkers[talker_id]["n_bwd_flows"]
    fwd_flows_rate = talkers[talker_id]["fwd_flows_rate"]
    bwd_flows_rate = talkers[talker_id]["bwd_flows_rate"]
    total_flow_duration = talkers[talker_id]["total_flow_duration"]
    mean_flow_duration = talkers[talker_id]["mean_flow_duration"]
    std_flow_duration = talkers[talker_id]["std_flow_duration"]
    var_flow_duration = talkers[talker_id]["var_flow_duration"]
    max_flow_duration = talkers[talker_id]["max_flow_duration"]
    min_flow_duration = talkers[talker_id]["min_flow_duration"]

    src_ip_sql_repr = ipv4_octal_to_int(src_ip)
    dst_ip_sql_repr = ipv4_octal_to_int(dst_ip)
    talker_start_time = unix_time_millis_to_datetime(talker_start_time)
    talker_end_time = unix_time_millis_to_datetime(talker_end_time)

    localdbconnector.safe_insert_query(
        "INSERT INTO Talkers (src_ip, dst_ip, src_host_id, dst_host_id," + \
        "talker_start_time, talker_end_time, talker_duration, n_fwd_flows, n_bwd_flows, fwd_flows_rate, bwd_flows_rate, total_flow_duration," + \
        "mean_flow_duration, std_flow_duration, var_flow_duration, max_flow_duration, min_flow_duration)" + \
        " VALUES (%s, %s, %s, %s," + \
        "%s, %s, %s, %s, %s, %s, %s, %s," + \
        "%s, %s, %s, %s, %s)",
        (src_ip, dst_ip, src_sql_host_id, dst_sql_host_id, talker_start_time, talker_end_time, talker_duration, n_fwd_flows, n_bwd_flows, fwd_flows_rate, bwd_flows_rate,\
        total_flow_duration, mean_flow_duration, std_flow_duration, var_flow_duration, max_flow_duration, min_flow_duration)
    )

    myresult = localdbconnector.select_query("SELECT id FROM Talkers WHERE src_ip = \"%s\" AND dst_ip = \"%s\"" %(src_ip, dst_ip))
    sql_talker_id = myresult[0][0]
    talkerid_sqltalkerid[talker_id] = sql_talker_id