#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  untitled.py
#  
#  Copyright 2012 Zach McCullough <nosrepa@gmail.com>
#  
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#  
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#  
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.

import json
import urllib.request
import time
import sys
import signal
from urllib.parse import urlencode
import http.cookiejar

def sigint_handler(signal, frame):
    '''Handles ^c'''
    print('Recieved SIGINT! Exiting...')
    sys.exit(0)

class Reddit(object):
    """Base class to perform the tasks of a redditor."""
    
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.cj = http.cookiejar.CookieJar() 
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.cj))
        self.opener.addheaders = [('User-agent', 'prune_bans.py')]
        self._login()
    
    def _request(self, url, body=None):
        if body is not None:
            body = urlencode(body).encode('utf-8')
        with self.opener.open(url, data=body) as w:
            time.sleep(2)
            return json.loads(w.read().decode('utf-8'))
    
    def _login(self):
        print("Logging in as {}.".format(self.username))
        body = {'user' :self.username, 'passwd' : self.password, 'api_type' : 'json'}
        resp = self._request('https://www.reddit.com/api/login', body)
        self.modhash = resp['json']['data']['modhash']
    
    def post(self, url, body):
        """Sends a POST to the url and returns the json as a dict."""
        
        if 'api_type' not in body: body['api_type'] = 'json'
        
        body['uh'] = self.modhash
        
        return self._request(url, body)

    
    def get(self, url):
        if not url.endswith('.json'): url += '.json'
        return self._request(url)

def main():
    return 0

if __name__ == '__main__':
    main()

