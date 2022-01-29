# V8-Memory-Forensics-Plugins

The V8 Engine used for Javascript can contain valuable information for investigators that resides within volatile RAM. THis repo is a tool to triage memory dumps to discover, determine, and present data by traversing V8 data strctures.

As of now this plugin only works within Windows 10 and the plugin is ran on volatility2. In the future the plugin may be updated to Volatility3 depending on the requests.

This work has been funded under the NSA Grant: TODO

# Repository Structure

The layout of this repository is as follows:
1. [Juypter-Notebook](data/custom/V8_recovery_analysis.ipynb) - the location of how we verified our results and information related to links of memory dumps that can be used to test V8. This is a Jupyter-notebook containing data from 10 memory dumps that can be found in the V8 Dataset section. Additionally, there is a folder custom that contains the CSV file used for this notebook. As well as the custom script used for the user object memory image.

2. [V8MapScan.py](plugins/V8MapScan.py) - This is the volatility plugin created to analyze memory dumps containing the V8 JavaScript Engine. It is written in volatility2 currrently and may be updated to volatility3.

# V8 Dataset

For this research, created was a dataset that can be used by anyone to analyze the objects that were found from a memory dump.
These dumps were created with a modified version of the plugin that would write stats to a csv. The jupyter-notebook containining this informatio The memory images used for the creation set can be found from (LINK HERE TOOD).
Depending on changes in volatility, it is subject to change and new developments with the plugin.

# Usage

The plugin makes use of the volatility3 framework and memory dumps to look at processes such as node, discord, etc. 


# Authors
