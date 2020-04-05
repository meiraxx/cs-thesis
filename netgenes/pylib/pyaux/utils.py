import os
import datetime
from dpkt.compat import compat_ord

class Colors:
    RED = '\033[91m'
    DRED = '\033[31m'
    GREEN = '\033[92m'
    DGREEN = '\033[32m'
    BLUE = '\033[94m'
    DBLUE = '\033[34m'
    YELLOW = '\033[93m'
    DYELLOW = '\033[33m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    
class OperatingSystem:
    # https://stackoverflow.com/questions/1392413/calculating-a-directorys-size-using-python
    def get_dir_size(start_path):
        """Sum all file sizes inside directory, including subdirectories"""
        total_size = 0
        for dirpath, dirnames, filenames in os.walk(start_path):
            for f in filenames:
                fp = os.path.join(dirpath, f)
                # skip if it is symbolic link
                if not os.path.islink(fp):
                    total_size += os.path.getsize(fp)

        return total_size

    def get_size_str(size_bytes):
        """Format byte-size string"""
        size_str = (str(round(size_bytes/(1024**2), 3)) + " MBs (megabytes)") if (size_bytes < 1024**3) \
            else (str(round(size_bytes/(1024**3), 3)) + " GBs (gigabytes)")

        return size_str

def datetime_to_unixtime(datetime_str):
    time_scale_factor = 1000.0
    datetime_format1 = "%Y-%m-%d %H:%M:%S.%f"
    datetime_format2 = "%Y-%m-%d %H:%M:%S"
    try:
        datetime_obj = datetime.datetime.strptime(datetime_str, datetime_format1)
    except ValueError:
        datetime_obj = datetime.datetime.strptime(datetime_str, datetime_format2)
    epoch = datetime.datetime.utcfromtimestamp(0)
    return (datetime_obj - epoch).total_seconds() * time_scale_factor

def unixtime_to_datetime(ms_timestamp):
    time_scale_factor = 1000.0
    datetime_format1 = "%Y-%m-%d %H:%M:%S.%f"
    datetime_format2 = "%Y-%m-%d %H:%M:%S"
    try:
        datetime_obj = datetime.datetime.utcfromtimestamp(ms_timestamp/time_scale_factor).strftime(datetime_format1)
    except ValueError:
        datetime_obj = datetime.datetime.utcfromtimestamp(ms_timestamp/1000.0).strftime(datetime_format2)
    return datetime_obj

def make_header_string(string, fwd_separator="-", bwd_separator="-", big_header_factor=1):
    """Transforms a string into an header"""
    fwd_separator_line = fwd_separator*len(string)
    bwd_separator_line = bwd_separator*len(string)

    header_string = Colors.BOLD + fwd_separator_line*big_header_factor + "\n" +\
        string + "\n" + bwd_separator_line*big_header_factor + Colors.ENDC
    return header_string