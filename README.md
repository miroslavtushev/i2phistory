# i2phistory

i2phistory is a plugin for Volatility suite that extracts the website history artifacts from i2p.exe process.

First, you need to install Volatility on your machine and all required dependencies. Please, refer to the official documentation on how to do that. An important step would be to make sure that yara is installed, because i2phistory relies on it. Once everything is installed, copy i2p.py and yara_rules.txt into your plugins directory.

To invoke the plugin, simply type 
```
python vol.py --plugins=myplugins --profile=Win10x64_18362
-f ../windows-e2392d36.vmem i2phistory
```
Replace the memory sample name and the plugins folder name with your own.
