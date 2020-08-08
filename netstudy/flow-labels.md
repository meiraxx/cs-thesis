### Dataset Author Labelling

CIC-IDS-2017 labels are present in the "GeneratedLabelledFlows.zip" file.  
CTU-13 labels are present in the &lt;file name&gt;.pcap.netflow.labeled files.  

The previous files, present in the "author-labeled-flows" directory, are served as input to "normalize-dataset-flows.py", which outputs their normalized versions to the "normalized-labeled-flows" directory.  

The NetGenes-extracted CSV files are present in the "netgenes-unlabeled-csv-data-files" directory, which are labeled using the "map-normalized-to-netgenes-data.py" script, building the "netgenes-labeled-csv-data-files" directory.  

The labeled NetGenes-extracted CSV files can then be mongo-imported using the "mongo-import-csv-data-files.py" script with "netgenes-labeled-csv-data-files" as first and only argument. From this point on, we have two datasets saved in Mongo Databases which we will analyze and test classification filters with a last script: "network-object-classifier.py".

