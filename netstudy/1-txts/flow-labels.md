### Dataset Author Labelling

Datasets
- CIC-IDS-2017 labels ("GeneratedLabelledFlows" directory, &lt;week-day name&gt;-\*.csv)
- CTU-13 labels (&lt;capture name&gt;.binetflow files)

The previous files, present in the "s0-author-labeled-flows" directory, are served as input to "s0-clean-dataset-normalize-flows.py", which outputs the normalized flow versions and clean datasets (remove useless fields, handle bad data, etc.) to the "s2-author-normalized-labeled-flows" directory.  

The NetGenes-extracted CSV files are present in the "s1-netgenes-unlabeled-csv-data-files" directory, and may then be mongo-imported using the "s1-mongo-import-csv-data-files.py" script. Then, with the help of the "s2-author-normalized-labeled-flows", the mongo-imported datasets are labeled using the "s2-map-normalized-to-netgenes-data.py" script, and all auxiliary files may be deleted safely ("s1-\*" and "s2-\*" directories).  

From this point on, we have two datasets saved in Mongo Databases which we will analyze and test classification filters (optionally, ML classifiers) with a last script: "network-object-classifiers.py".

