import volatility.plugins.common as common
import volatility.utils as utils
import volatility.conf as conf
import volatility.plugins.taskmods as taskmods
from volatility.renderers import TreeGrid
import tempfile
import os
import re
import shutil
import string

try:
    import yara
    has_yara = True
except ImportError:
    has_yara = False

class i2phistory(common.AbstractWindowsCommand):
    '''
    This plugin collects all urls (history) from i2p.exe. It supports both yara and built-in regex.
    I found built-in regex to give a lot of false-positives, such as websites never clicked on directly
    by a user, but appeared in html-code of other web-sites, for example. Yara seems to be giving more precise
    results so far, but more testing has to be done.
    '''

    patterns = {
        r"http[s]?://(?P<domain>(www\.)?[-a-zA-Z0-9]+\.[-a-zA-Z0-9]+)/[-a-zA-Z0-9%#\?=&\./:\+_]*" : "URL",
    }

    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        self._config.add_option('YARA', short_option = 'y', default = False, help = 'Use YARA for matching patterns instead of built-in regex', 
                action = 'store_true')

    def calculate(self):
        if not has_yara:
            debug.error("Please install Yara from https://plusvic.github.io/yara/")
        # initialize memdump
        memdump_conf = self.build_conf()
        p = taskmods.MemDump(memdump_conf)
        # dump i2p's memory
        p.execute()
        del p
        
        dump_path = os.path.join(memdump_conf.DUMP_DIR, os.listdir(memdump_conf.DUMP_DIR)[0])

        ret_list = list()
        print "Searching..."
        if self._config.YARA:
            base = os.path.dirname(os.path.abspath(__file__))
            yara_rule = yara.compile(base + "/yara_rule.txt")
            with open(dump_path, "rb") as f:
                data = f.read()
            for match in yara_rule.match(data=data):
                for url in match.strings:
                    # to extract domain and cut off the end
                    for pat in self.patterns.viewkeys():
                        match = re.search(pat, url[2])
                        if match:
                            ret = match.group(0)
                            link = re.sub(match.group("domain")[::-1], "", ret)
                            if link not in [x.full for x in ret_list]:
                                ret_list.append(Url(match.group("domain"), link))   
        else:
            for s in self.strings(dump_path, 6):
                for pat in self.patterns.viewkeys():
                    match = re.search(pat, s)
                    if match:
                        ret = match.group(0)
                        link = re.sub(match.group("domain")[::-1], "", ret)
                        if link not in [x.full for x in ret_list]:
                            ret_list.append(Url(match.group("domain"), link))   
                
        # clean up
        shutil.rmtree(memdump_conf.DUMP_DIR)
        return ret_list

    def generator(self, data):
        for link in data:
		    yield (0, [
		        str(link.domain),
		        str(link.full)
		    ])

    def unified_output(self, data):
        tree = [
            ("Domain", str),
            ("Full Name", str)
            ]
        return TreeGrid(tree, self.generator(data))

    def build_conf(self):
        '''Creates a configuration object for memdump'''
        memdump_conf = conf.ConfObject()
        memdump_conf.readonly = {}
        memdump_conf.PROFILE = self._config.PROFILE
        memdump_conf.LOCATION = self._config.LOCATION
        memdump_conf.NAME = "i2p.exe"
        memdump_conf.DUMP_DIR = tempfile.mkdtemp()
        return memdump_conf

    def strings(self, filename, min=4):
        '''Mimics UNIX's strings'''
        with open(filename, "rb") as f:
            result = ""       
            for c in f.read():
                if c in string.printable:
                    result += c
                    continue
                if len(result) >= min:
                    yield result
                result = ""
                if len(result) >= min:  # catch result at EOF
                    yield result

class Url(object):
    def __init__(self, domain, full):
        self.domain = domain
        self.full = full      

