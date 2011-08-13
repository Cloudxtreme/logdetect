#83.2.xx.yy webnull.kablownia.org - [10/Aug/2011:13:51:42 +0200] "GET /projekty.html HTTP/1.0" 200 1895 "http://webnull.kablownia.org/" "Mozilla/5.0 (Windows NT 5.1; rv:5.0.1) Gecko/20100101 Firefox/5.0.1"

#::ffff:192.168.1.xx oneill - [26/Apr/2011:18:02:42 +0200] "GET /sites/zuadmin/sls.js HTTP/1.1" 304 0 "http://oneill/sites/zuadmin/?seo_id=login" "Mozilla/5.0 (X11; U; Gentoo Linux; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/11.0.696.3"

import re, urllib

class LogdetectExtension:
    parent = ""

    def __init__(self, parent):
        self.parent = parent

    def parseAll(self, data):
        itemsList = list()

        # parse all changed lines
        for Item in data:
            Find = re.findall("([0-9\.\:a-zA-Z]+) ([0-9\.\:a-zA-Z]+) - \[(.*)\] \"(.*)\" ([0-9]+) ([0-9]+) \"(.*)\" \"(.*)\"", Item)

            if len(Find) == 0:
                continue

            IP = Find[0][0]

            # REMOVE IPV6 support
            if ':' in Find[0][0]:
                exp = Find[0][0].split(":")
                IP = exp[(len(exp)-1)]

            matches = dict()
            matches['filter'] = urllib.unquote(Find[0][3]) # example: GET /blabla HTTP/1.1
            matches['uid'] = IP # example: 10.0.0.3
            matches['all'] = Find[0] # All matches
            itemsList.append(matches)

        return itemsList
