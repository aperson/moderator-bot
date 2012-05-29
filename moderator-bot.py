#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#  moderator-bot.py
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
import re
import signal
import sys
from urllib.parse import urlencode
import http.cookiejar
from credentials import *

def p(data):
        print(time.strftime('\033[2K[\033[31m%y\033[39m/\033[31m%m\033[39m/\033[31m%d\033[39m]'
                             '[\033[31m%H\033[39m:\033[31m%M\033[39m:\033[31m%S\033[39m] ') + data)

def sigint_handler(signal, frame):
    '''Handles ^c'''
    p('Recieved SIGINT! Exiting...')
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
        p("Logging in as {}.".format(self.username))
        body = {'user' :self.username, 'passwd' : self.password, 'api_type' : 'json'}
        resp = self._request('https://www.reddit.com/api/login', body)
        self.modhash = resp['json']['data']['modhash']
    
    def post(self, url, body):
        """Sends a POST to the url and returns the json as a dict."""
        
        if 'api_type' not in body: body['api_type'] = 'json'
        
        body['uh'] = self.modhash
        
        return self._request(url, body)

    
    def get(self, url):
        """Sends a GET to the url and returns the json as a dict."""
        if '.json' not in url: url += '.json'
        return self._request(url)
    
    def nuke(self, post, comment=None, hide=True):
        '''Remove/hide/comment.'''
        remove = {'spam' : 'False', 'r' : post['subreddit'],
                                           'id' : post['name'], 'executed' : 'removed'}
        self.post('http://www.reddit.com/api/remove', remove)
        if hide:
            hide = {'id' : post['name']}
            self.post('http://www.reddit.com/api/hide', hide)
        if comment:
            comment = {'thing_id' : post['name'], 'text' : comment}
            submission = self.post('http://www.reddit.com/api/comment',
                                 comment)['json']['data']['things'][0]['data']['id']
            distinguish = {'id' : submission, 'executed' : 'distinguishing...'}
            self.post('http://www.reddit.com/api/distinguish/yes', distinguish)

def main():    
    sleep_time = 60 * 5
    r = Reddit(USERNAME, PASSWORD)
    p('Started monitoring submissions on /r/{}.'.format(SUBREDDIT))
    
    # Lets define our filters. They should return True in boolean context if match is positive
    def suggestion_filter(post):
        """Removes [Suggestion] submissions that eitherare not self post or do not have
        self-text."""
        suggestion = re.compile(r'''.*?(?:^|\s|\[|<|\(|{)?(sug*estion|idea)(?:$|\s|\]|>|\)|:|})''',
                                 re.I)
        template_1 = ("This submission has been removed automatically.  According to our [subreddit"
                      " rules](/r/{sub}/faq), suggestion posts must be self-posts only.  If you fee"
                      "l this was in error, please [message the moderators](/message/compose/?to=/r"
                      "/{sub}&subject=Removal%20Dispute).".format(sub=SUBREDDIT))
        template_2 = ("This submission has been removed automatically.  According to our [subreddit"
                      " rules](/r/{sub}/faq), suggestion posts must have a description along with t"
                      "hem, which is something you cannot convey with only a title.  If you feel th"
                      "is was in error, please [message the moderators](/message/compose/?to={sub}&"
                      "subject=Removal%20Dispute).".format(sub=SUBREDDIT))
        if 'title' in post and suggestion.match(post['title']):
            if post['domain'] != 'self.{}'.format(SUBREDDIT):
                p('Found [Suggestion] submission that is not a self post, removing.')
                r.nuke(post, template_1)
                return True
            elif not post['selftext']:
                p('Found [Suggestion] submission that has no self-text, removing.')
                r.nuke(post, template_2)
                return True
    
    def fixed_filter(post):
        """Removes [Fixed] posts."""
        fixed = re.compile(r'''.*?(?:\[|<|\(|{|^)(fixed)(?:\]|>|\)|:|})''', re.I)
        template_1 = ("This submission has been removed automatically.  According to our [subreddit"
                      " rules](/r/{sub}/faq), [Fixed] posts are not allowed.  If you feel this was "
                      "in error, please [message the moderators](/message/compose/?to={sub}&subject"
                      "=Removal%20Dispute).".format(sub=SUBREDDIT))
        if 'title' in post and fixed.match(post['title']):
            p('Found [fixed] post, removing.')
            r.nuke(post, template_1)
            return True
    
    def ip_filter(post):
        """Removes submissions and comments that have an ip in them."""
        def ip_in(text):
            ip = re.compile(r'''.*?(\d{1,3}(?:\.\d{1,3}){3})''')
            if ip.match(text):
                for i in ip.findall(text)[0].split('.'):
                    try:
                        if not int(i) <= 255:
                            return False
                    except ValueError:
                        # this shouldn't happen
                        return False
                return True
        template_1 = ("This submission has been removed automatically.  According to our [subreddit"
                      " rules](/r/{sub}/faq), server advertisements are not allowed.  If you feel t"
                      "his was in error, please [message the moderators](/message/compose/?to={sub}"
                      "&subject=Removal%20Dispute).".format(sub=SUBREDDIT))
        if 'title' in post:
            if ip_in(post['title']):
                p('Found server ad in title, removing.')
                r.nuke(post, template_1)
                return True
            elif post['selftext'] and ip_in(post['selftext']):
                p('Found server ad in selftext, removing.')
                r.nuke(post, template_1)
                return True
        elif 'body' in post:
            if ip_in(post['body']):
                p('Found server ad in comment, removing.')
                r.nuke(post, hide=False)
                return True
    
    # and throw them into a list of filters
    filters = [suggestion_filter, fixed_filter, ip_filter]
    
    # main loop
    while True:
        p('Getting feed...')
        new_listing = r.get('http://reddit.com/r/{}/new/.json?sort=new'.format(SUBREDDIT))
        modqueue_listing = r.get('http://reddit.com/r/{}/about/modqueue.json'.format(SUBREDDIT))
        comments_listing = r.get('http://reddit.com/r/{}/comments/.json'.format(SUBREDDIT))
        feed = []
        feed.extend(new_listing['data']['children'])
        feed.extend(modqueue_listing['data']['children'])
        feed.extend(comments_listing['data']['children'])
        with open('test.json', 'w') as f:
            f.write(json.dumps(feed))
        for item in feed:
            item = item['data']
            # I know using 'is True' isn't the 'right' way, but reddit's api is weird here
            # and I wanted to explicitly show it
            if item['banned_by'] is True and item['author'] != USERNAME:
                for f in filters:
                    if f(item): break
        p('Sleeping for {} seconds.'.format(sleep_time))
        time.sleep(sleep_time)

if __name__ == '__main__':
    signal.signal(signal.SIGINT, sigint_handler)
    main()
