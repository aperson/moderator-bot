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
        print(time.strftime('\r\033[K\033[2K[\033[31m%y\033[39m/\033[31m%m\033[39m/\033[31m%d'
                             '\033[39m][\033[31m%H\033[39m:\033[31m%M\033[39m:\033[31m%S\033[39m] ')
                              + data)

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
        self.opener.addheaders = [('User-agent', 'moderator-bot.py')]
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
        suggestion = re.compile(r'''.*?((?:\[|<|\(|{)?sug*estion(?:\s|s?\]|s?>|s?\)|:|})|'''
                                 r'''(?:^|\[|<|\(|{)ideas?(?:\]|>|\)|:|}))''',
                                 re.I | re.S)
        
        template_1 = ("This submission has been removed automatically.  According to our [subreddit"
                      " rules](/r/{sub}/faq), suggestion posts must be self-posts only.  If you fee"
                      "l this was in error, please [message the moderators](/message/compose/?to=/r"
                      "/{sub}&subject=Removal%20Dispute&message={link}).")
        template_2 = ("This submission has been removed automatically.  According to our [subreddit"
                      " rules](/r/{sub}/faq), suggestion posts must have a description along with t"
                      "hem, which is something you cannot convey with only a title.  If you feel th"
                      "is was in error, please [message the moderators](/message/compose/?to={sub}&"
                      "subject=Removal%20Dispute&message={link}).")
        if 'title' in post and suggestion.match(post['title']):
            link = 'http://reddit.com/r/{}/comments/{}/'.format(SUBREDDIT, post['id'])
            if post['domain'] != 'self.{}'.format(SUBREDDIT):
                p('Found [Suggestion] submission that is not a self post, removing:')
                p(link)
                r.nuke(post, template_1.format(sub=SUBREDDIT, link=link))
                return True
            elif not post['selftext']:
                p('Found [Suggestion] submission that has no self-text, removing:')
                p(link)
                r.nuke(post, template_2.format(sub=SUBREDDIT, link=link))
                return True
    
    def fixed_filter(post):
        """Removes [Fixed] posts."""
        fixed = re.compile(r'''.*?(?:\[|<|\(|{)(fixed)(?:\]|>|\)|:|})''', re.I | re.S)
        template_1 = ("This submission has been removed automatically.  According to our [subreddit"
                      " rules](/r/{sub}/faq), [Fixed] posts are not allowed.  If you feel this was "
                      "in error, please [message the moderators](/message/compose/?to={sub}&subject"
                      "=Removal%20Dispute&message={link}).")
        if 'title' in post and fixed.match(post['title']):
            link = 'http://reddit.com/r/{}/comments/{}/'.format(SUBREDDIT, post['id'])
            p('Found [fixed] post, removing.')
            p(link)
            r.nuke(post, template_1.format(sub=SUBREDDIT, link=link))
            return True
    
    def ip_filter(post):
        """Removes submissions and comments that have an ip in them."""
        def ip_in(text):
            ip = re.compile(r'''.*?(\d{1,3}(?:\.\d{1,3}){3})''', re.DOTALL)
            if "Minecraft has crashed!" in text:
                return False
            if ip.match(text):
                try:
                    split_ip = [int(i) for i in ip.findall(text)[0].split('.')]
                except ValueError:
                    return False
                if split_ip[:3] == [10, 0, 0]:
                    return False
                elif split_ip[:3] == [127, 0, 0]:
                    return False
                elif split_ip[:2] == [192, 168]:
                    return False
                elif split_ip == [0] * 4:
                    return False
                for i in split_ip:
                    if not i <= 255:
                        return False
                return True
        template_1 = ("This submission has been removed automatically.  According to our [subreddit"
                      " rules](/r/{sub}/faq), server advertisements are not allowed.  If you feel t"
                      "his was in error, please [message the moderators](/message/compose/?to={sub}"
                      "&subject=Removal%20Dispute&message={link}).")
        if 'title' in post:
            link = 'http://reddit.com/r/{}/comments/{}/'.format(SUBREDDIT, post['id'])
            if ip_in(post['title']) or 'planetminecraft.com/server/' in post['url']:
                p('Found server ad in title, removing:')
                P(link)
                r.nuke(post, template_1.format(sub=SUBREDDIT, link=link))
                return True
            elif post['selftext'] and ip_in(post['selftext']):
                p('Found server ad in selftext, removing:')
                p(link)
                r.nuke(post, template_1.format(sub=SUBREDDIT, link=link))
                return True
        elif 'body' in post:
            if ip_in(post['body']):
                p('Found server ad in comment, removing:')
                p('http://reddit.com/r/{}/comments/{}/a/{}'.format(SUBREDDIT, post['link_id'][3:],
                                                                    post['id']))
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
        for i in (new_listing, modqueue_listing, comments_listing):
            feed.extend(i['data']['children'])
        for item in feed:
            item = item['data']
            # I know using 'is True' isn't the 'right' way, but reddit's api is weird here
            # and I wanted to explicitly show it
            if item['banned_by'] is True and \
                item['author'] != USERNAME and not item['approved_by']:
                for f in filters:
                    if f(item): break
        p('Sleeping for {} seconds.'.format(sleep_time))
        time.sleep(sleep_time)

if __name__ == '__main__':
    signal.signal(signal.SIGINT, sigint_handler)
    main()
