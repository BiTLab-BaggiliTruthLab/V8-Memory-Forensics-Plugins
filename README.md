# V8-Memory-Forensics-Plugins

The V8 Engine used for Javascript can contain valuable information for investigators that resides within volatile RAM. THis repo is a tool to triage memory dumps to discover, determine, and present data by traversing V8 data strctures.

As of now this plugin only works within Windows 10 and the plugin is ran on volatility2. In the future the plugin may be updated to Volatility3 depending on the requests.

This work has been funded under the TODO GRANT...

# Repository Structure

The layout of this repository is as follows:
1. [Data](data/README.md) - the location of how we verified our results and information related to links of memory dumps that can be used to test V8.
2. [Plugin](plugin/README.md) - this contains the volatility3 plugin that can be used for volatility2.

# Usage

The plugin makes use of the volatility3 framework and memory dumps to look at processes such as node, discord, etc. 


# Authors
