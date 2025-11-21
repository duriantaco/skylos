import os  # Used
import sys  # Used
import json  # Unused - should be detected
import datetime  # Unused - should be detected

# Import with alias
import pandas as pd  # Used
import numpy as np  # Unused - should be detected

# From imports
from collections import defaultdict, Counter  # Both used
from itertools import cycle, chain, repeat  # Only cycle is used


# Function using imports
def get_files():
    """Function that uses several imports."""
    current_dir = os.getcwd()
    path_sep = os.path.sep

    df = pd.DataFrame({"files": os.listdir(current_dir)})

    counts = Counter(sys.argv)
    defaults = defaultdict(int)

    # use just one of the itertools
    for i in cycle([1, 2, 3]):
        if i > 10:
            break
        defaults[i] += 1

    return df, counts, defaults
