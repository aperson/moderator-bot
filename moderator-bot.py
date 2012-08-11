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

try:
    from credentials import *
except:
    USERNAME = 'botname'
    PASSWORD = 'botpass'
    SUBREDDIT = 'subtomonitor'
    SUBOPTS = {'type': 'restricted', 'link_type': 'any', 'show_media': True, 'allow_top': True}
    EDITSTART = '[](/mbeditstart)'
    EDITSTOP = '[](/mbeditstop)'
    GREENTEXT = "[](/redstone_lamp_on '{} is online')"
    REDTEXT = "[](/redstone_lamp_off '{} is offline')"
    BOTSUB = 'botprivatesub'
    LOGFILE = '/some/file/to/log/to.html'
    SERVERDOMAINS = 'http://example.com/server_domain_list.csv'


def p(data, end='\n'):
    print(time.strftime('\r\033[K\033[2K[\033[31m%y\033[39m/\033[31m%m\033[39m/\033[31m%d'
        '\033[39m][\033[31m%H\033[39m:\033[31m%M\033[39m:\033[31m%S\033[39m] ') + data, end=end)

def logToDisk(log_text):
    log_start = ("<html><head><link rel=\"stylesheet\" type=\"text/css\" href=\"style.css\" /><titl"
        "e>{username} modlog</title></head><body>".format(username=USERNAME))
    log_end = "</body>"
    entry_base = "<div class=\"entry\"><span>{time}</span> {data}</div>".format(time=
        time.strftime('[%y/%m/%d][%H:%M:%S]'), data=log_text)
    with open(LOGFILE) as l:
        log = l.read().strip()
    log = log[len(log_start):-len(log_end)]
    split_log = log.split('\n')
    if len(split_log) < 1000:
        log = '\n'.join(split_log)
    else:
        log = '\n'.join(split_log[1:])
    with open(LOGFILE, 'w') as l:
        l.write(log_start + entry_base + log + log_end)

def sigint_handler(signal, frame):
    '''Handles ^c'''
    p('Recieved SIGINT! Exiting...')
    sys.exit(0)

def mojangStatus():
    '''Returns the status indicator for /r/Minecraft's sidebar'''
    opener = urllib.request.build_opener()
    with opener.open('http://status.mojang.com/check') as w:
        status = json.loads(w.read().decode('utf-8'))
    text = ''
    for x in status:
        for y in x:
            if x[y] == 'green':
                text += GREENTEXT.format(y)
            elif x[y] == 'red':
                text += REDTEXT.format(y)
    return text


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

    def nuke(self, post, action):
        '''Remove/hide/comment.'''
        remove = {'r': post['subreddit'],
            'id': post['name'], 'executed': action}
        if action == 'remove':
            remove['spam'] = 'false'
        self.post('http://www.reddit.com/api/remove', remove)
        if 'title' in post:
            hide = {'id': post['name']}
            self.post('http://www.reddit.com/api/hide', hide)

    def rts(self, username, tag='', subreddit=None):
        """Checks the account age of a user and rts' them if they are less than a day old."""
        if not subreddit:
            subreddit = BOTSUB
        DAY = 60 * 60 * 24

        user = self.get("http://reddit.com/user/{}/about.json".format(username))

        if (time.time() - user['data']['created_utc']) <= DAY:
            p('{} is less than a day old. Submitting to /r/moderator_bot:'.format(username))
            body = {'title': '{} {}'.format(username, tag), 'sr': subreddit,
                    'url': 'http://reddit.com/u/' + username, 'kind': 'link'}
            submission = self.post('http://www.reddit.com/api/submit', body)
            p('http://redd.it/{}'.format(submission['json']['data']['id']))

    def sidebar(self, subreddit, text):
        """Edits the sidebar in subreddit in-between the allowed tags set by EDITSTART and
        EDITSTOP"""
        sub = self.get('http://www.reddit.com/r/{}/about.json'.format(subreddit))['data']
        regex = r'''{}.*?{}'''.format(re.escape(EDITSTART), re.escape(EDITSTOP))
        text = EDITSTART + text + EDITSTOP
        sub['description'].replace('&amp;', '&'
            ).replace('&gt;', '>'
            ).replace('&lt;', '<')
        sidebar = re.sub(regex, text, sub['description'])
        body = {'sr': sub['name'], 'title': sub['title'],
            'public_description': sub['public_description'], 'description': sidebar,
            'type': SUBOPTS['type'], 'link_type': SUBOPTS['link_type'],
            'show_media': SUBOPTS['show_media'], 'allow_top': SUBOPTS['allow_top']}
        if sub['header_title']:
            body['header-title'] = sub['header_title']
        if sub['over18']:
            body['over_18'] = True
        self.post('http://www.reddit.com/api/site_admin', body)


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
        self.log_text = ""
        self.ban = False
        self.report_subreddit = None

    def filterComment(self, comment):
        raise NotImplementedError

    def filterSubmission(self, submission):
        raise NotImplementedError

    def runFilter(self, post):
        if 'title' in post:
            try:
                if self.filterSubmission(post):
                    logToDisk(self.log_text)
                    return True
            except NotImplementedError:
                pass
        elif 'body' in post:
            try:
                if self.filterComment(post):
                    logToDisk(self.log_text)
                    return True
            except NotImplementedError:
                pass


class Suggestion(Filter):
    def __init__(self):
        Filter.__init__(self)
        self.regex = re.compile(r'''((?:\[|<|\(|{|\*|\|)?sug*estion(?:\s|s?\]|s?>|s?\)|:|}|\*|\|'''
            r''')|(?:^|\[|<|\(|{|\*|\|)ideas?(?:\]|>|\)|:|}|\*|\|))''', re.I)

    def filterSubmission(self, submission):
        if self.regex.search(submission['title']):
            link = 'http://reddit.com/r/{}/comments/{}/'.format(submission['subreddit'],
                submission['id'])

            if submission['domain'] != 'self.{}'.format(submission['subreddit']):
                reason = "suggestions must be self-post only"
                self.log_text = "Found [Suggestion] submission that is not a self post"
                self.comment = self.comment_template.format(sub=submission['subreddit'],
                    reason=reason, link=link)
                p(self.log_text + ":")
                p(link)
                return True
            elif not submission['selftext']:
                self.log_text = "Found [Suggestion] submission that has no self text"
                reason = ("suggestion posts must have a description along with them, which is somet"
                    "hing you cannot convey with only a title")
                self.comment = self.comment_template.format(sub=submission['subreddit'],
                    reason=reason, link=link)
                p(self.log_text + ":")
                p(link)
                return True


class Fixed(Filter):
    def __init__(self):
        Filter.__init__(self)
        self.regex = re.compile(r'''[\[|<\({\*]fixed[\]|>\):}\*]''', re.I)
        self.log_text ="Found [Fixed] submission"

    def filterSubmission(self, submission):
        if self.regex.search(submission['title']):
            link = 'http://reddit.com/r/{}/comments/{}/'.format(submission['subreddit'],
                submission['id'])
            reason = "[Fixed] submissions are not allowed"
            self.comment = self.comment_template.format(sub=submission['subreddit'],
                reason=reason, link=link)
            p(self.log_text + ":")
            p(link)
            return True


class ServerAd(Filter):
    def __init__(self):
        Filter.__init__(self)
        self.opener = urllib.request.build_opener()
        self.opener.addheaders = [('User-agent', 'moderator-bot.py v2')]
        with self.opener.open(SERVERDOMAINS) as w:
            self.domain_list = w.read().decode('utf-8').split('\n')
        p('Found {} domains in online blacklist.'.format(len(self.domain_list)))
        self.regex = re.compile(r'''(?:^|\s|ip:)(\d{1,3}(?:\.\d{1,3}){3})(?:\s|$|:)''', re.I)
        self.tag = "[Server Spam]"

    def _server_in(self, text):
        if text:
            for i in self.domain_list:
                if i.lower() in text.lower():
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
        if self._server_in(submission['title']) or self._server_in(submission['selftext']) \
            or self._server_in(submission['url'][7:]):
            self.log_text = "Found server advertisement in submission"
            link = 'http://reddit.com/r/{}/comments/{}/'.format(submission['subreddit'],
                submission['id'])
            reason = "server advertisements are not allowed"
            self.comment = self.comment_template.format(sub=submission['subreddit'],
                reason=reason, link=link)
            p(self.log_text + ":")
            p(link)
            return True

    def filterComment(self, comment):
        if self._server_in(comment['body']):
            self.comment = ''
            self.log_text = "Found server advertisement in comment"
            p(self.log_text + ":")
            p('http://reddit.com/r/{}/comments/{}/a/{}'.format(comment['subreddit'],
                comment['link_id'][3:], comment['id']))
            return True


class FreeMinecraft(Filter):
    def __init__(self):
        Filter.__init__(self)
        self.regex = re.compile(r'''(?:free|cracked)?-?minecraft-?(?:install|codes?|rewards?|gif'''
            r'''t-?codes?(?:-?generator)?|acc(?:t|ount)s?|now|forever)(?:\.blogspot)?\.(?:me|info|'''
            r'''com|net|org|ru|co\.uk|us)''', re.I)
        self.action = 'spammed'
        self.ban = True

    def filterSubmission(self, submission):
        if self.regex.search(submission['title']) or self.regex.search(submission['selftext']) \
            or self.regex.search(submission['url']):
            link = 'http://reddit.com/r/{}/comments/{}/'.format(submission['subreddit'],
                submission['id'])
            self.log_text = "Found free Minecraft link in submission"
            reason = "free minecraft links are not allowed"
            self.comment = self.comment_template.format(sub=submission['subreddit'],
                reason=reason, link=link)
            p(self.log_text + ":")
            p(link)
            return True

    def filterComment(self, comment):
        if self.regex.search(comment['body']):
            self.comment = ''
            self.log_text = "Found free minecraft link in comment"
            p(self.log_text + ":")
            p('http://reddit.com/r/{}/comments/{}/a/{}'.format(comment['subreddit'],
                comment['link_id'][3:], comment['id']))
            return True


class AmazonReferral(Filter):
    def __init__(self):
        Filter.__init__(self)
        self.regex = re.compile(r'''amazon\.(?:at|fr|com|ca|cn|de|es|it|co\.(?:jp|uk))*.?tag=*.?'''
            r'''-20''', re.I)
        self.tag = "[Amazon Referral Spam]"
        self.action = 'spammed'
        self.report_subreddit = 'reportthespammers'

    def filterSubmission(self, submission):
        if self.regex.search(submission['title']) or self.regex.search(submission['selftext']) \
            or self.regex.search(submission['url']):
            self.log_text = "Found Amazon referral link in submission"
            link = 'http://reddit.com/r/{}/comments/{}/'.format(submission['subreddit'],
                submission['id'])
            p(self.log_text +":")
            p(link)
            return True

    def filterComment(self, comment):
        if self.regex.search(comment['body']):
            self.log_text = "Found Amazon referral link in comment"
            p(self.log_text + ":")
            p('http://reddit.com/r/{}/comments/{}/a/{}'.format(comment['subreddit'],
                comment['link_id'][3:], comment['id']))
            return True


class ShortUrl(Filter):
    def __init__(self):
        Filter.__init__(self)
        self.regex = re.compile(r'''(?:bit\.ly|goo\.gl|adf\.ly|is\.gd|t\.co|tinyurl\.com|j\.mp|'''
            r'''tiny\.cc|soc.li|ultrafiles\.net|linkbucks\.com|lnk\.co|qvvo\.com)/''', re.I)

    def filterSubmission(self, submission):
        if self.regex.search(submission['title']) or self.regex.search(submission['selftext']) \
        or self.regex.search(submission['url']):
            link = 'http://reddit.com/r/{}/comments/{}/'.format(submission['subreddit'],
                submission['id'])
            self.log_text = "Found short url in submission"
            reason = "short urls are not allowed"
            self.comment = self.comment_template.format(sub=submission['subreddit'],
                reason=reason, link=link)
            p(self.log_text + ":")
            p(link)
            return True

    def filterComment(self, comment):
        if self.regex.search(comment['body']):
            self.comment = ''
            self.log_text = "Found short url in comment"
            p(self.log_text + ":")
            p('http://reddit.com/r/{}/comments/{}/a/{}'.format(comment['subreddit'],
                comment['link_id'][3:], comment['id']))
            return True


class Failed(Filter):
    def __init__(self):
        Filter.__init__(self)

    def filterSubmission(self, submission):
        link = 'http://reddit.com/r/{}/comments/{}/'.format(submission['subreddit'],
                submission['id'])
        if submission['domain'].startswith('['):
            self.log_text = "Found submission with formatting in the url"
            self.comment = ("You've seemed to try to use markdown or other markup in the url field"
                " when you made this submission. Markdown formatting is only for self text and comm"
                "enting; other formatting code is invalid on reddit. When you make a link submissio"
                "n, please only enter the bare link in the url field.\n\nFeel free to try submitti"
                "ng again.")
            p(self.log_text + ":")
            p(link)
            return True
        elif '.' not in submission['domain']:
            self.log_text = "Found submission with invalid url"
            self.comment =("The submission you've made does not have a valid url in it.  Please tr"
                "y resubmitting and make special attention to what you're typing/pasting in the url"
                " field.")
            p(self.log_text + ":")
            p(link)
            return True


class Minebook(Filter):
    def __init__(self):
        Filter.__init__(self)
        self.regex = re.compile(r'''minebook\.me''', re.I)
        self.action = 'spammed'

    def filterSubmission(self, submission):
        if self.regex.search(submission['title']) or self.regex.search(submission['selftext']) \
            or submission['domain'] == 'minebook.me':
            self.log_text = "Found minebook in submission"
            p(self.log_text + ":")
            p('http://reddit.com/r/{}/comments/{}/'.format(submission['subreddit'],
                submission['id']))
            return True


    def filterComment(self, comment):
        if self.regex.search(comment['body']):
            self.log_text = "Found minebook in comment"
            p(self.log_text + ":")
            p('http://reddit.com/r/{}/comments/{}/a/{}'.format(comment['subreddit'],
                comment['link_id'][3:], comment['id']))


class SelfLinks(Filter):
    def __init__(self):
        Filter.__init__(self)
        self.regex = re.compile(r'''^http://\S*$''')

    def filterSubmission(self, submission):
        if submission['selftext']:
            for i in submission['selftext'].split():
                if not self.regex.match(i):
                    break
            else:
                self.comment = ("This submission has been removed automatically.  You appear to ha"
                    "ve only included links in your self-post with no explanatory text.  Please res"
                    "ubmit or edit your post accordingly.")
                self.log_text = "Found self-post that only contained links"
                p(self.log_text + ":")
                p('http://reddit.com/r/{}/comments/{}/'.format(submission['subreddit'],
                    submission['id']))
                return True


def main():
    sleep_time = 60 * 3
    r = Reddit(USERNAME, PASSWORD)
    last_status = None
    p('Started monitoring submissions on /r/{}.'.format(SUBREDDIT))

    filters = [Suggestion(), Fixed(), ServerAd(), FreeMinecraft(), AmazonReferral(),ShortUrl(),
        Failed(), Minebook(), SelfLinks()]

    # main loop
    while True:
        p('Getting feed...', end='')
        new_listing = r.get('http://reddit.com/r/{}/new/.json?sort=new'.format(SUBREDDIT))
        modqueue_listing = r.get('http://reddit.com/r/{}/about/modqueue.json'.format(SUBREDDIT))
        comments_listing = r.get('http://reddit.com/r/{}/comments/.json'.format(SUBREDDIT))
        feed = []
        processed = []

        status = mojangStatus()
        p('Checking Mojang servers...', end='')
        if status != last_status:
            p('Mojang server status changed, updating sidebar')
            r.sidebar(SUBREDDIT, status)
        last_status = status

        for i in (new_listing, modqueue_listing, comments_listing):
            feed.extend(i['data']['children'])
        for item in feed:
            item = item['data']
            # I know using 'is True' isn't the 'right' way, but reddit's api is weird here
            # and I wanted to explicitly show it
            if item['banned_by'] is True and item['author'] != USERNAME and not \
                item['approved_by'] and item['author'] != 'tweet_poster':
                for f in filters:
                    if item['id'] not in processed and f.runFilter(item):
                        r.nuke(item, f.action)
                        if f.comment:
                            comment = {'thing_id': item['name'], 'text': f.comment}
                            submission = r.post('http://www.reddit.com/api/comment',
                                 comment)['json']['data']['things'][0]['data']['id']
                            distinguish = {'id': submission, 'executed': 'distinguishing...'}
                            r.post('http://www.reddit.com/api/distinguish/yes', distinguish)
                        if f.tag:
                            r.rts(item['author'], tag=f.tag, subreddit=f.report_subreddit)
                        if f.ban:
                            p('Banning http://reddit.com/u/{}'.format(item['author']))
                            body = {'action': 'add', 'type': 'banned', 'name': item['author'],
                                'id': '#banned', 'r': item['subreddit']}
                            r.post('http://www.reddit.com/api/friend', body)
                        processed.append(item['id'])
                        break
        for i in range(sleep_time):
            p('Next scan in {} seconds...'.format(sleep_time - i), end='')
            time.sleep(1)

if __name__ == '__main__':
    signal.signal(signal.SIGINT, sigint_handler)
    main()
