import math

# metrics


def calc_metrics(tp, tn, fp, fn, total_results):
	assert(total_results==tp+tn+fp+fn)
	# Class / Non-class results
	class_results = tp+fp
	non_class_results = tn+fn
	# Correct / Incorrect results
	correct_results = tp+tn
	incorrect_results = fp+fn
	# Positive / Negative results
	positive_results = tp+fn
	negative_results = tn+fp

	Overall_Accuracy = round(float(correct_results)/float(total_results), 5)
	# PS: 0.9981695086696897
	Sensitivity = round(float(tp)/float(positive_results), 5)
	# PS: 0.9964398037488992
	Specificity = round(float(tn)/float(negative_results), 5)
	# PS: 0.9996243664490461
	Fallout = round(float(fp)/float(negative_results), 5)
	# PS: 0.0003756335509538976
	Miss_Rate = round(float(fn)/float(positive_results), 5)
	# PS: 0.003560196251100767
	Precision = round(float(tp)/float(class_results), 5)
	# PS: 0.9995520080764742
	F1_Score = round(float(2*tp)/float(2*tp+incorrect_results), 5)
	# PS: 0.9979934795961759
	Mcc = round(float(tp*tn - fp*fn)/float(math.sqrt((class_results)*(positive_results)*(negative_results)*(non_class_results))), 5)
	# PS: 0.9979934795961759

	print("===========================")
	print("===========================")
	print("TP: %d"%(tp))
	print("TN: %d"%(tn))
	print("FP: %d"%(fp))
	print("FN: %d"%(fn))
	print("---------------------------")
	print("Overall Accuracy: %.3f%%"%(Overall_Accuracy*100))
	print("Sensitivity (TPR): %.3f%%"%(Sensitivity*100))
	print("Specificity (TNR): %.3f%%"%(Specificity*100))
	print("Fallout (FPR): %.3f%%"%(Fallout*100))
	print("Miss Rate (FNR): %.3f%%"%(Miss_Rate*100))
	print("F1 Score: %.3f%%"%(F1_Score*100))
	print("Mcc: %.3f%%"%(Mcc*100))
	print("===========================")
	print("===========================")
	return

if __name__ == "__main__":
	# ---------
	# PORT SCAN
	# ---------
	# Friday flows: 347994
	friday_flows = 347994
	# "Port Scan" flows: 158890
	friday_PortScan_flows = 158890
	# True Positive Results: correctly classified class flows as class
	tp = 158414
	# False Positive Results: incorrectly classified non-class flows as class
	fp = 71
	# False Negative Results: incorrectly classified class flows as non-class
	fn = 566
	# False Positive Results: correctly classified non-class flows as non-class
	tn = friday_flows-(tp+fp+fn)

	print("Friday - TCP Port Scan")
	calc_metrics(tp, tn, fp, fn, friday_flows, friday_PortScan_flows)

