#!/bin/bash

# =====================================
# Installing the 'pymongoimport' module
# =====================================
#pip install --upgrade pymongoimport

mongod_pid=$(pgrep mongod)

# ==========================
# Check if mongod is running
# ==========================
if ! [ "$mongod_pid" ]; then
	echo "Process 'mongod' is not running, please run it."
	exit 1
fi

# ==========================================================
# Grab CSV files and import them to the local mongo instance
# ==========================================================

# -----------------
# Using MongoImport
# -----------------
#https://stackoverflow.com/questions/4686500/how-to-use-mongoimport-to-import-csv
#https://docs.mongodb.com/manual/reference/program/mongoimport/

# -------------------
# Using PyMongoImport
# -------------------
#https://pymongodbimport.readthedocs.io/en/latest/pymongoimport.html