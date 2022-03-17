# V8-Memory-Forensics-Plugins

The V8 Engine used for Javascript can contain valuable information for investigators that resides within volatile RAM. This repo is a tool to triage memory dumps to discover, determine, and present data by traversing V8 data structures. This repo contains all the information about the volatility plugin 

This work has been funded under the NSA Grant: H98230-20-1-0328

# Repository Structure

The layout of this repository is as follows:
1. [Jupyter-Notebook](data/V8_recovery_analysis.ipynb) - the location of how we verified our results and information related to links of memory dumps that can be used to test V8. This is a notebook containing data from 10 memory dumps that can be found in the V8 Dataset section. Additionally, there is a folder custom that contains the CSV file used for this notebook. As well as the custom script used for the user object memory image.

2. [V8MapScan.py](plugins/V8MapScan.py) - This is the volatility plugin created to analyze memory dumps containing the V8 JavaScript Engine. It is written in volatility2 currrently and may be updated to volatility3.

3. [V8_32BitVtypes.py](plugins/V8_32BitVTypes.py) - This is a version that contains usage of vtypes that works for 32 bit applications discord. This style would be used for porting over to volatility3's ISF.

# V8 Dataset

For this research, created was a dataset that can be used by anyone to analyze the objects that were found from a memory dump.
These dumps were created with a modified version of the plugin that would write stats to a csv. The jupyter-notebook containining this informatio The memory images used for the creation set can be found from [here](https://unhnewhaven-my.sharepoint.com/:f:/g/personal/hjohn5_unh_newhaven_edu/EpcBPe3HJbFHmVOhcKpFe3MBGR3jgHc99Jkv16QNDKALXA?e=tARW24).
Depending on changes in volatility, it is subject to change and new developments with the plugin.

# Usage

## V8_instancetype_addr
```bash
$ python vol.py -f dump.vmem v8_instancetypeaddr
```


## V8_extractobjects
```bash
$ python vol.py -f dump.vmem v8_extractobjects
```

## V8_findalltypes
```bash
$ python vol.py -f dump.vmem v8_findalltypes
```

## v8extractprops

```bash
$ python vol.py -f dump.vmem v8_extractprops
```

The plugin makes use of the volatility2 framework and memory dumps to look at processes such as node, discord, etc. 


# Authors

- Enoch Wang
- Samuel Zurowski - [https://samuelzurowski.com/](https://samuelzurowski.com/) 
- Orion Duffy
- Tyler Thomas
- Ibrahim Baggili
