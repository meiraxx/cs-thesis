# HOSTS
hostid_sqlhostid = dict()
for host_id in hosts:
    # host features
    n_talkers = hosts[host_id]["n_talkers"]
    rate_talkers = hosts[host_id]["rate_talkers"]

    ip_sql_repr = ipv4_octal_to_int(host_id)

    localdbconnector.safe_insert_query(
        "INSERT INTO Hosts (ip, n_talkers, rate_talkers) VALUES (%s, %s, %s)",
        (host_id, n_talkers, rate_talkers)
    )

    myresult = localdbconnector.select_query("SELECT id FROM Hosts WHERE ip = \"%s\"" %(host_id))
    sql_host_id = myresult[0][0]
    hostid_sqlhostid[host_id] = sql_host_id