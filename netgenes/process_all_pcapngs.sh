#!/bin/bash


pcapng_dir="data-files/pcapng"
extraction_logs_dir="1-extraction-logs"
ctu13_extraction_logs_dir="1-extraction-logs/1-ctu13"
cicids2017_extraction_logs_dir="1-extraction-logs/0-cicids2017"

if [[ -d "$pcapng_dir" ]]
then
	for pcapng_file in $(ls $pcapng_dir)
	do
		pcapng_fullpath="$pcapng_dir/$pcapng_file"
		# Verbose; Output = CSV
		./netgenes-tool.py $pcapng_fullpath -v | tee >(sed 's/\x1b\[[0-9;]*m//g' > "$extraction_logs_dir/${pcapng_file%.*}.txt")
	done
fi

# CTU-13
mv "$extraction_logs_dir/botnet-capture-20110810-neris.txt" "$ctu13_extraction_logs_dir/ctu13-01-Neris1.txt"
mv "$extraction_logs_dir/botnet-capture-20110811-neris.txt" "$ctu13_extraction_logs_dir/ctu13-02-Neris2.txt"
mv "$extraction_logs_dir/botnet-capture-20110812-rbot.txt" "$ctu13_extraction_logs_dir/ctu13-03-Rbot1.txt"
mv "$extraction_logs_dir/botnet-capture-20110815-rbot-dos.txt" "$ctu13_extraction_logs_dir/ctu13-04-Rbot2.txt"
mv "$extraction_logs_dir/botnet-capture-20110815-fast-flux.txt" "$ctu13_extraction_logs_dir/ctu13-05-Virut1.txt"
mv "$extraction_logs_dir/botnet-capture-20110816-donbot.txt" "$ctu13_extraction_logs_dir/ctu13-06-Menti-Donbot.txt"
mv "$extraction_logs_dir/botnet-capture-20110816-sogou.txt" "$ctu13_extraction_logs_dir/ctu13-07-Sogou.txt"
mv "$extraction_logs_dir/botnet-capture-20110816-qvod.txt" "$ctu13_extraction_logs_dir/ctu13-08-Murlo-Qvod.txt"
mv "$extraction_logs_dir/botnet-capture-20110817-bot.txt" "$ctu13_extraction_logs_dir/ctu13-09-Neris3.txt"
mv "$extraction_logs_dir/botnet-capture-20110818-bot.txt" "$ctu13_extraction_logs_dir/ctu13-10-Rbot3.txt"
mv "$extraction_logs_dir/botnet-capture-20110818-bot-2.txt" "$ctu13_extraction_logs_dir/ctu13-11-Rbot4.txt"
mv "$extraction_logs_dir/botnet-capture-20110819-bot.txt" "$ctu13_extraction_logs_dir/ctu13-12-NSIS.txt"
mv "$extraction_logs_dir/botnet-capture-20110815-fast-flux-2.txt" "$ctu13_extraction_logs_dir/ctu13-13-Virut2.txt"

# CICIDS-2017
mv "$extraction_logs_dir/Monday-WorkingHours.txt" "$cicids2017_extraction_logs_dir/cicids2017-1-Monday.txt"
mv "$extraction_logs_dir/Tuesday-WorkingHours.txt" "$cicids2017_extraction_logs_dir/cicids2017-2-Tuesday.txt"
mv "$extraction_logs_dir/Wednesday-WorkingHours.txt" "$cicids2017_extraction_logs_dir/cicids2017-3-Wednesday.txt"
mv "$extraction_logs_dir/Thursday-WorkingHours.txt" "$cicids2017_extraction_logs_dir/cicids2017-4-Thursday.txt"
mv "$extraction_logs_dir/Friday-WorkingHours.txt" "$cicids2017_extraction_logs_dir/cicids2017-5-Friday.txt"