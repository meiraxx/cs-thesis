#!/usr/bin/env python3

"""
MySql Connector
"""

import mysql.connector
import sys

mydb = mysql.connector.connect(
  user="root",
  password="mySqlPassword123456*",
  host="127.0.0.1",
  #database="tese",
  #auth_plugin='mysql_native_password'
)
"""
ip = ipaddress.IPv4Address("127.0.0.1")
ip_int_repr = int(ip)
ip_hex_repr = hex(ip_int_repr)
ip_str_repr = str(ip)
ip_bin_repr = bin(ip_int_repr)
ip_sql_repr = hex(int(ip))[2:]
"""

mycursor = mydb.cursor()
mycursor.execute("CREATE DATABASE tese")

def safe_insert_query(sql_query, val, _print=False):
	try:
		mycursor.execute(sql_query, val)
		mydb.commit()
		if _print:
			print("%s record(s) inserted" %(mycursor.rowcount))
	except mysql.connector.errors.IntegrityError as e:
		# constraint not satisfied (example: unique IP)
		pass

def select_query(sql_query):
	mycursor.execute(sql_query)
	myresult = mycursor.fetchall()
	return myresult

def delete_all(table_name):
	sql = "DELETE FROM %s WHERE \"1\"=\"1\"" %(table_name)
	mycursor.execute(sql)
	mydb.commit()
	print("%s record(s) deleted from table \"%s\"" %(mycursor.rowcount, table_name))

#safe_insert_query("INSERT INTO Hosts (ip, n_dialogues, rate_dialogues) VALUES (%s, %s, %s)", ("ip_sql_repr placeholder", 2, 0.1))
#safe_insert_query("INSERT INTO Hosts (ip, n_dialogues, rate_dialogues) VALUES (%s, %s, %s)", ("ip_sql_repr placeholder", 2, 0.1))
#delete_all("Hosts")

# CREATE DATABASE
#mycursor.execute("CREATE DATABASE mydatabase")


# CREATE TABLE
#mycursor.execute("CREATE TABLE customers (name VARCHAR(255), address VARCHAR(255))")

# INSERT
#sql_query = "INSERT INTO customers (name, address) VALUES (%s, %s)"
#val = ("John", "Highway 21")
#mycursor.execute(sql_query, val)
#mydb.commit()
#print(mycursor.rowcount, "record inserted.")

# SELECT
#mycursor.execute("SELECT * FROM customers")
#myresult = mycursor.fetchall()
#for x in myresult:
#	print(x)

# DELETE
#sql = "DELETE FROM Hosts WHERE \"1\"=\"1\""
#mycursor.execute(sql)
#mydb.commit()
#print(mycursor.rowcount, "record(s) deleted")