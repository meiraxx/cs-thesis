import autogluon as ag
from autogluon import TabularPrediction as task
from utils import *

# use on cic-ids-2017 portscan and benign
train_data = task.Dataset(file_path="ipv4-tcp-bihosts.csv")
train_data = train_data.head(500) # subsample 500 data points for faster demo
print(train_data.head())

label_column = 'benign'
print("Summary of benign variable: \n", train_data[label_column].describe())

dir = 'agModels-predictClass' # specifies folder where to store trained models
predictor = task.fit(train_data=train_data, label=label_column, output_directory=dir)

test_data = task.Dataset(file_path="ipv4-tcp-bihosts.csv")
y_test = test_data[label_column]  # values to predict
test_data_nolab = test_data.drop(labels=[label_column],axis=1) # delete label column to prove we're not cheating
print(test_data_nolab.head())