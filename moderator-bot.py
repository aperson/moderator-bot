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
        '\033[39m][\033[31m%H\033[39m:\033[31m%M\033[39m:\033[31m%S\033[39m] ') + data)


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
        self.opener.addheaders = [('User-agent', 'moderator-bot.py v2')]
        self._login()

    def _request(self, url, body=None):
        if body is not None:
            body = urlencode(body).encode('utf-8')
        with self.opener.open(url, data=body) as w:
            time.sleep(2)
            return json.loads(w.read().decode('utf-8'))

    def _login(self):
        p("Logging in as {}.".format(self.username))
        body = {'user': self.username, 'passwd': self.password, 'api_type': 'json'}
        resp = self._request('https://www.reddit.com/api/login', body)
        self.modhash = resp['json']['data']['modhash']

    def post(self, url, body):
        """Sends a POST to the url and returns the json as a dict."""

        if 'api_type' not in body:
            body['api_type'] = 'json'

        body['uh'] = self.modhash

        return self._request(url, body)

    def get(self, url):
        """Sends a GET to the url and returns the json as a dict."""
        if '.json' not in url:
            url += '.json'
        return self._request(url)

    def nuke(self, post, action, comment=None):
        '''Remove/hide/comment.'''
        remove = {'spam': 'False', 'r': post['subreddit'],
            'id': post['name'], 'executed': action}
        self.post('http://www.reddit.com/api/remove', remove)
        if 'title' in post:
            hide = {'id': post['name']}
            self.post('http://www.reddit.com/api/hide', hide)
        if comment:
            comment = {'thing_id': post['name'], 'text': comment}
            submission = self.post('http://www.reddit.com/api/comment',
                                 comment)['json']['data']['things'][0]['data']['id']
            distinguish = {'id': submission, 'executed': 'distinguishing...'}
            self.post('http://www.reddit.com/api/distinguish/yes', distinguish)

    def rts(self, username, tag=''):
        """Checks the account age of a user and rts' them if they are less than a day old."""

        DAY = 60 * 60 * 24

        user = self.get("http://reddit.com/user/{}/about.json".format(username))

        if (time.time() - user['data']['created_utc']) <= DAY:
            p('{} is less than a day old. Submitting to /r/moderator_bot:'.format(username))
            body = {'title': '{} {}'.format(username, tag), 'sr': 'moderator_bot',
                    'url': 'http://reddit.com/u/' + username, 'kind': 'link'}
            submission = self.post('http://www.reddit.com/api/submit', body)
            p('http://redd.it/{}'.format(submission['json']['data']['id']))


class Filter(object):
    """Base filter class"""
    def __init__(self):
        self.regex = None
        self.comment_template = ("##This submission has been removed automatically.\nAccording to "
            "our [subreddit rules](/r/{sub}/faq), {reason}.  If you feel this was in error, please "
            "[message the moderators](/message/compose/?to=/r/{sub}&subject=Removal%20Dispute&messa"
            "ge={link}).")
        self.comment = ""
        self.tag = ""
        self.action = 'remove'

    def filterComment(self, comment):
        raise NotImplementedError

    def filterSubmission(self, submission):
        raise NotImplementedError

    def runFilter(self, post):
        if 'title' in post:
            try:
                if self.filterSubmission(post):
                    return True
            except NotImplementedError:
                pass
        elif 'body' in post:
            try:
                if self.filterComment(post):
                    return True
            except NotImplementedError:
                pass


class Suggestion(Filter):
    def __init__(self):
        Filter.__init__(self)
        self.regex = re.compile(r'''((?:\[|<|\(|{)?sug*estion(?:\s|s?\]|s?>|s?\)|:|})|(?:^|\[|<|'''
            '''\(|{)ideas?(?:\]|>|\)|:|}))''', re.I)

    def filterSubmission(self, submission):
        if self.regex.search(submission['title']):
            link = 'http://reddit.com/r/{}/comments/{}/'.format(submission['subreddit'],
                submission['id'])

            if submission['domain'] != 'self.{}'.format(submission['subreddit']):
                reason = "suggestions must be self-post only"
                self.comment = self.comment_template.format(sub=submission['subreddit'],
                    reason=reason, link=link)
                p("Found [Suggestion] submission that is not a self post:")
                p(link)
                return True
            elif not submission['selftext']:
                reason = ("suggestion posts must have a description along with them, which is somet"
                    "hing you cannot convey with only a title")
                self.comment = self.comment_template.format(sub=submission['subreddit'],
                    reason=reason, link=link)
                p("Found [Suggestion] submisison that has no self text:")
                p(link)
                return True


class  Fixed(Filter):
    def __init__(self):
        Filter.__init__(self)
        self.regex = re.compile(r'''[\[|<\({]fixed[\]>\):}]''', re.I)

    def filterSubmission(self, submission):
        if self.regex.search(submission['title']):
            link = 'http://reddit.com/r/{}/comments/{}/'.format(submission['subreddit'],
                submission['id'])
            reason = "[Fixed] submissions are not allowed"
            self.comment = self.comment_template.format(sub=submission['subreddit'],
                reason=reason, link=link)
            p("Found [Fixed] submission:")
            p(link)
            return True


class Ip(Filter):
    def __init__(self):
        Filter.__init__(self)
        self.regex = re.compile(r'''(?:^|\s|ip:)(\d{1,3}(?:\.\d{1,3}){3})(?!/|-|\.)''', re.I)
        self.tag = "[Server Spam]"

    def _server_in(self, text):
        if text:
            if 'planetminecraft.com/server/' in text.lower():
                return True
            try:
                ip = self.regex.findall(text)
                if ip:
                    split_ip = [int(i) for i in ip[0].split('.')]
                else:
                    return False
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

    def filterSubmission(self, submission):
        if self._server_in(submission['title']) or self._server_in(submission['selftext']):
            link = 'http://reddit.com/r/{}/comments/{}/'.format(submission['subreddit'],
                submission['id'])
            reason = "server advertisements are not allowed"
            self.comment = self.comment_template.format(sub=submission['subreddit'],
                reason=reason, link=link)
            p("Found server advertisement in submission:")
            p(link)
            return True

    def filterComment(self, comment):
        if self._server_in(comment['body']):
            p("Found server ad in comment:")
            p('http://reddit.com/r/{}/comments/{}/a/{}'.format(comment['subreddit'],
                comment['link_id'][3:], comment['id']))
            return True


class FreeMinecraft(Filter):
    def __init__(self):
        Filter.__init__(self)
        self.regex = re.compile(r'''(?:free|cracked)?-?minecraft-?(?:codes?|rewards?|gift-?codes?'''
                              r'''(?:-?generator)?)\.(?:me|info|com|net|org|ru|co\.uk)''', re.I)
        self.tag = "[Free Minecraft Spam]"

    def filterSubmission(self, submission):
        if self.regex.search(submission['title']) or self.regex.search(submission['selftext']):
            link = 'http://reddit.com/r/{}/comments/{}/'.format(submission['subreddit'],
                submission['id'])
            reason = "free minecraft links are not allowed"
            self.comment = self.comment_template.format(sub=submission['subreddit'],
                reason=reason, link=link)
            p("Found free Minecraft link in submission:")
            p(link)
            return True

    def filterComment(self, comment):
        if self.regex.search(comment['body']):
            p("Found free minecraft link in comment:")
            p('http://reddit.com/r/{}/comments/{}/a/{}'.format(comment['subreddit'],
                comment['link_id'][3:], comment['id']))
            return True


class AmazonReferral(Filter):
    def __init__(self):
        Filter.__init__(self)
        self.regex = re.compile(r'''amazon\.(?:at|fr|com|ca|cn|de|es|it|co\.(?:jp|uk))*.?tag=*.?'''
            r'''-20''', re.I)
        self.tag = "[Amazon Referral Spam]"

    def filterSubmission(self, submission):
        if submission['domain'] is 'picshd.com' or self.regex.search(submission['selftext']):
            link = 'http://reddit.com/r/{}/comments/{}/'.format(submission['subreddit'],
                submission['id'])
            p("Found Amazon referral link in submission:")
            p(link)
            return True

    def filterComment(self, comment):
        if self.regex.search(comment['body']):
            p("Found Amazon referral link in comment:")
            p('http://reddit.com/r/{}/comments/{}/a/{}'.format(comment['subreddit'],
                comment['link_id'][3:], comment['id']))
            return True


class ShortUrl(Filter):
    def __init__(self):
        Filter.__init__(self)
        self.regex = re.compile(r'''(?:bit\.ly|goo\.gl|adf\.ly|is\.gd|t\.co|tinyurl\.com|j\.mp|'''
            r'''tiny\.cc|soc.li)/''', re.I)

    def filterSubmission(self, submission):
        if self.regex.search(submission['title']) or self.regex.search(submission['selftext']):
            link = 'http://reddit.com/r/{}/comments/{}/'.format(submission['subreddit'],
                submission['id'])
            reason = "short urls are not allowed"
            self.comment = self.comment_template.format(sub=submission['subreddit'],
                reason=reason, link=link)
            p("Found short url in submission:")
            p(link)
            return True

    def filterComment(self, comment):
        if self.regex.search(comment['body']):
            p("Found short in comment:")
            p('http://reddit.com/r/{}/comments/{}/a/{}'.format(comment['subreddit'],
                comment['link_id'][3:], comment['id']))
            return True


class Failed(Filter):
    def __init__(self):
        Filter.__init__(self)

    def filterSubmission(self, submission):
        if submission['domain'].startswith('['):
            link = 'http://reddit.com/r/{}/comments/{}/'.format(submission['subreddit'],
                submission['id'])
            self.comment = ("You've seemed to try to use markdown or other markup in the url field"
                " when you made this submission. Markdown formatting is only for self text and comm"
                "enting; other formatting code is invalid on reddit. When you make a link submissio"
                "n, please only enter the bare link in the url field.\n\nFeel free to try submitti"
                "ng again.")
            p("Found link submission with formatting in the url:")
            p(link)
            return True


class PicsHd(Filter):
    def __init__(self):
        Filter.__init__(self)
        self.regex = re.compile(r'''http://(?:www\.)?picshd\.com/\w*''', re.I)
        self.action = 'spammed'

    def filterSubmission(self, submission):
        if self.regex.search(submission['title']) or self.regex.search(submission['selftext']):
            p("Found picshd.com in submission:")
            p('http://reddit.com/r/{}/comments/{}/'.format(submission['subreddit'],
                submission['id']))
            return True

    def filterComment(self, comment):
        if self.regex.search(comment['body']):
            p("Found picshd.com in comment:")
            p('http://reddit.com/r/{}/comments/{}/a/{}'.format(comment['subreddit'],
                comment['link_id'][3:], comment['id']))
            return True

def main():
    sleep_time = 60 * 5
    r = Reddit(USERNAME, PASSWORD)
    p('Started monitoring submissions on /r/{}.'.format(SUBREDDIT))

    filters = [Suggestion(), Fixed(), Ip(), FreeMinecraft(), AmazonReferral(), ShortUrl(),
        Failed(), PicsHd()]

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
            if item['banned_by'] is True and item['author'] != USERNAME and not \
                item['approved_by']:
                for f in filters:
                    if f.runFilter(item):
                        if f.comment:
                            r.nuke(item, f.action, comment=f.comment)
                        else:
                            r.nuke(item, f.action)
                        if f.tag:
                            r.rts(item['author'], tag=f.tag)
                        break
        p('Sleeping for {} seconds.'.format(sleep_time))
        time.sleep(sleep_time)

if __name__ == '__main__':
    signal.signal(signal.SIGINT, sigint_handler)
    main()
