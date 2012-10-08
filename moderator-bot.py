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
import shelve
from contextlib import contextmanager
from collections import defaultdict

try:
    from credentials import *  # NOQA
except:
    USERNAME = 'botname'
    PASSWORD = 'botpass'
    SUBREDDIT = 'subtomonitor'
    EDITSTART = '[](#mbeditstart)'
    EDITSTOP = '[](#mbeditstop)'
    GREENTEXT = "[](#status_green '{} is online')"
    REDTEXT = "[](#status_red '{}' is offline')"
    BOTSUB = 'botprivatesub'
    LOGFILE = '/some/file/to/log/to.html'
    SERVERDOMAINS = 'http://example.com/server_domain_list.csv'
    DATABASEFILE = '/some/path'
    BANNEDSUBS = ['some', 'list']


def p(data, end='\n'):
    print(time.strftime(
        '\r\033[K\033[2K[\033[31m%y\033[39m/\033[31m%m\033[39m/\033[31m%d'
        '\033[39m][\033[31m%H\033[39m:\033[31m%M\033[39m:\033[31m%S\033[39m] ') + data, end=end)


def logToDisk(log_text):
    log_start = (
        "<html><head><link rel=\"stylesheet\" type=\"text/css\" href=\"style.css\" /><titl"
        "e>{username} modlog</title></head><body>".format(username=USERNAME))
    log_end = "</body>"
    entry_base = "<div class=\"entry\"><span>{time}</span> {data}</div>".format(
        time=time.strftime('[%y/%m/%d][%H:%M:%S]'), data=log_text)
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
    try:
        with opener.open('http://status.mojang.com/check') as w:
            status = json.loads(w.read().decode('utf-8'))
    except urllib.error.HTTPError:
        return None
    except http.client.BadStatusLine:
        return None
    text = []
    for x in status:
        for y in x:
            if x[y] == 'green':
                p("{} is green".format(y), end="")
                text.append(GREENTEXT.format(y))
            elif x[y] == 'red':
                p("{} is red".format(y), end="")
                text.append(REDTEXT.format(y))
    return ''.join(text)


class Database(object):
    '''Handles reading and writing from a shelve 'database'.'''
    def __init__(self, path):
        self.path = path

    @contextmanager
    def open(self):
        s = shelve.open(self.path, writeback=True)
        try:
            yield s
        finally:
            s.close()


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
        if action == 'remove' or action == 'spammed':
            remove = {
                'r': post['subreddit'], 'id': post['name'], 'executed': action}
            if action == 'remove':
                remove['spam'] = 'false'
            self.post('http://www.reddit.com/api/remove', remove)
        if action == 'report':
            report = {'id': post['name']}
            self.post('http://www.reddit.com/api/report', report)
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
        sub = self.get('http://www.reddit.com/r/{}/about/edit/.json'.format(subreddit))['data']
        regex = r'''{}.*?{}'''.format(re.escape(EDITSTART), re.escape(EDITSTOP))
        text = EDITSTART + text + EDITSTOP
        to_replace = (('&amp;', '&'), ('&gt;', '>'), ('&lt;', '<'))
        for i in to_replace:
            sub['description'] = sub['description'].replace(*i)
        sidebar = re.sub(regex, text, sub['description'])
        body = {
            'sr': sub['subreddit_id'], 'title': sub['title'],
            'public_description': sub['public_description'], 'description': sidebar,
            'type': sub['subreddit_type'], 'link_type': sub['content_options'],
            'show_media': sub['show_media'], 'allow_top': sub['default_set'],
            'over_18': sub['over_18'], 'header-title': sub['header_hover_text'],
            'prev_description_id': sub['prev_description_id'],
            'prev_public_description_id': sub['prev_public_description_id'],
            'wikimode': sub['wikimode'], 'wiki_edit_age': sub['wiki_edit_age'],
            'wiki_edit_karma': sub['wiki_edit_karma']}
        self.post('http://www.reddit.com/api/site_admin', body)


class Filter(object):
    """Base filter class"""
    def __init__(self):
        self.regex = None
        self.comment_template = (
            "##This submission has been removed automatically.\nAccording to our [subreddit rules]("
            "/r/{sub}/faq), {reason}.  If you feel this was in error, please [message the moderator"
            "s](/message/compose/?to=/r/{sub}&subject=Removal%20Dispute&message={link}).")
        self.comment = ""
        self.tag = ""
        self.action = 'remove'
        self.log_text = ""
        self.ban = False
        self.report_subreddit = None
        self.nuke = True
        self.opener = urllib.request.build_opener()
        self.opener.addheaders = [('User-agent', 'moderator-bot.py v2')]

    def filterComment(self, comment):
        raise NotImplementedError

    def filterSubmission(self, submission):
        raise NotImplementedError

    def runFilter(self, post):
        if 'title' in post:
            try:
                if self.filterSubmission(post):
                    if self.log_text:
                        logToDisk(self.log_text)
                    return True
            except NotImplementedError:
                pass
        elif 'body' in post:
            try:
                if self.filterComment(post):
                    if self.log_text:
                        logToDisk(self.log_text)
                    return True
            except NotImplementedError:
                pass


class Suggestion(Filter):
    def __init__(self):
        Filter.__init__(self)
        self.regex = re.compile(
            r'''((?:\[|<|\(|{|\*|\|)?sug*estion(?:\s|s?\]|s?>|s?\)|:|}|\*|\|'''
            r''')|(?:^|\[|<|\(|{|\*|\|)ideas?(?:\]|>|\)|:|}|\*|\|))''', re.I)

    def filterSubmission(self, submission):
        if self.regex.search(submission['title']):
            link = 'http://reddit.com/r/{}/comments/{}/'.format(
                submission['subreddit'], submission['id'])

            if submission['domain'] != 'self.{}'.format(submission['subreddit']):
                reason = "suggestions must be self-post only"
                self.log_text = "Found [Suggestion] submission that is not a self post"
                self.comment = self.comment_template.format(
                    sub=submission['subreddit'], reason=reason, link=link)
                p(self.log_text + ":")
                p(link)
                return True
            elif not submission['selftext']:
                self.log_text = "Found [Suggestion] submission that has no self text"
                reason = (
                    "suggestion posts must have a description along with them, which is something y"
                    "ou cannot convey with only a title")
                self.comment = self.comment_template.format(
                    sub=submission['subreddit'], reason=reason, link=link)
                p(self.log_text + ":")
                p(link)
                return True


class Fixed(Filter):
    def __init__(self):
        Filter.__init__(self)
        self.regex = re.compile(r'''[\[|<\({\*]fixed[\]|>\):}\*]''', re.I)
        self.log_text = "Found [Fixed] submission"

    def filterSubmission(self, submission):
        if self.regex.search(submission['title']):
            link = 'http://reddit.com/r/{}/comments/{}/'.format(
                submission['subreddit'], submission['id'])
            reason = "[Fixed] submissions are not allowed"
            self.comment = self.comment_template.format(
                sub=submission['subreddit'], reason=reason, link=link)
            p(self.log_text + ":")
            p(link)
            return True


class ServerAd(Filter):
    def __init__(self):
        self.last_update = 0
        self.domain_list = []
        Filter.__init__(self)
        self._update_list()
        self.tag = "[Server Spam]"
        self.regex = re.compile(
            r'''(?:^|\s|ip(?:=|:)|\*)(\d{1,3}(?:\.\d{1,3}){3})\.?(?:\s|$|:|\*|!|\.|\?)''', re.I)

    def _update_list(self):
        if (time.time() - self.last_update) >= 1800:
            self.last_update = time.time()
            p('Updating domain blacklist...', end='')
            with self.opener.open(SERVERDOMAINS) as w:
                domain_list = w.read().decode('utf-8').split('\n')
            if len(self.domain_list) < len(domain_list):
                p('Found {} new domains in online blacklist.'.format(
                    len(domain_list) - len(self.domain_list)))
                self.domain_list = domain_list
            elif len(self.domain_list) > len(domain_list):
                p('Removed {} domains from the online blacklist'.format(
                    len(self.domain_list) - len(domain_list)))
                self.domain_list = domain_list

    def _server_in(self, text):
        self._update_list()
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

    def _imgur_check(self, url):
        '''Takes a imgur url and returns True if a server ad is found in the title or description'''
        url = url.replace('&amp;', '&')
        original_url = url
        p("Checking {}".format(original_url), end='')
        url = url.split('imgur.com/')[1]
        url = url.split('#')[0]
        if url.endswith('/'):
            url = url[:-1]
        if url.endswith('/all'):
            url = url[:-4]
        if '.' in url:
            return False

        image_list = []

        try:
            if url.startswith('a/'):
                url = url[2:].split('/')[0]
                with self.opener.open('https://api.imgur.com/2/album/{}.json'.format(url)) as w:
                    imgur = json.loads(w.read().decode('utf-8'))['album']
                    time.sleep(2)
                image_list.append({'title': imgur['title'], 'caption': imgur['description']})
                for i in imgur['images']:
                    image_list.append(i['image'])
            else:
                for i in re.split(r''',|&''', url):
                    with self.opener.open('https://api.imgur.com/2/image/{}.json'.format(i)) as w:
                        imgur = json.loads(w.read().decode('utf-8'))['image']
                        time.sleep(2)
                    image_list.append(imgur['image'])
        except urllib.error.HTTPError:
            p('Could not parse: {}'.format(original_url))
            return None

        for i in image_list:
            if i['caption']:
                if self._server_in(i['caption']):
                    return True
            if i['title']:
                if self._server_in(i['title']):
                    return True
        return False

    def filterSubmission(self, submission):
        if self._server_in(submission['title']) or\
            self._server_in(submission['selftext']) or\
                self._server_in(submission['url'][7:]):
            self.log_text = "Found server advertisement in submission"
            link = 'http://reddit.com/r/{}/comments/{}/'.format(
                submission['subreddit'], submission['id'])
            reason = "server advertisements are not allowed"
            self.comment = self.comment_template.format(
                sub=submission['subreddit'], reason=reason, link=link)
            p(self.log_text + ":")
            p(link)
            return True
        elif submission['domain'] == 'imgur.com':
            if self._imgur_check(submission['url']):
                self.log_text = "Found server advertisement in submission"
                link = 'http://reddit.com/r/{}/comments/{}/'.format(
                    submission['subreddit'], submission['id'])
                reason = "server advertisements are not allowed"
                self.comment = self.comment_template.format(
                    sub=submission['subreddit'], reason=reason, link=link)
                p(self.log_text + ":")
                p(link)
                return True
        elif submission['domain'] in ('m.youtube.com', 'youtube.com', 'youtu.be'):
            if 'media' in submission:
                if submission['media'] is not None:
                    if 'oembed' in submission['media']:
                        if self._server_in(submission['media']['oembed']['description']) or\
                                self._server_in(submission['media']['oembed']['title']):
                            return True

    def filterComment(self, comment):
        if self._server_in(comment['body']):
            self.comment = ''
            self.log_text = "Found server advertisement in comment"
            p(self.log_text + ":")
            p('http://reddit.com/r/{}/comments/{}/a/{}'.format(
                comment['subreddit'], comment['link_id'][3:], comment['id']))
            return True


class FreeMinecraft(Filter):
    def __init__(self):
        Filter.__init__(self)
        self.regex = re.compile(
            r'''(?:(?:free|cracked)?-?minecraft-?(?:install|'''
            r'''(?:gift-?)?codes?(?:-?gen(?:erator)?)?|rewards?|acc(?:t|ount)s?|now|forever)'''
            r'''(?:\.blogspot)?\.(?:me|info|com|net|org|ru|co\.uk|us)|epicfreeprizes\.com)''', re.I)
        self.action = 'spammed'
        self.ban = True

    def filterSubmission(self, submission):
        if self.regex.search(submission['title']) or\
            self.regex.search(submission['selftext']) or\
                self.regex.search(submission['url']):
            link = 'http://reddit.com/r/{}/comments/{}/'.format(
                submission['subreddit'], submission['id'])
            self.log_text = "Found free Minecraft link in submission"
            reason = "free minecraft links are not allowed"
            self.comment = self.comment_template.format(
                sub=submission['subreddit'], reason=reason, link=link)
            p(self.log_text + ":")
            p(link)
            return True

    def filterComment(self, comment):
        if self.regex.search(comment['body']):
            self.comment = ''
            self.log_text = "Found free minecraft link in comment"
            p(self.log_text + ":")
            p('http://reddit.com/r/{}/comments/{}/a/{}'.format(
                comment['subreddit'], comment['link_id'][3:], comment['id']))
            return True


class AmazonReferral(Filter):
    def __init__(self):
        Filter.__init__(self)
        self.regex = re.compile(
            r'''amazon\.(?:at|fr|com|ca|cn|de|es|it|co\.(?:jp|uk))*.?tag=*.?-20''', re.I)
        self.tag = "[Amazon Referral Spam]"
        self.action = 'spammed'
        self.report_subreddit = 'reportthespammers'

    def filterSubmission(self, submission):
        if self.regex.search(submission['title']) or\
            self.regex.search(submission['selftext']) or\
                self.regex.search(submission['url']):
            self.log_text = "Found Amazon referral link in submission"
            link = 'http://reddit.com/r/{}/comments/{}/'.format(
                submission['subreddit'], submission['id'])
            p(self.log_text + ":")
            p(link)
            return True

    def filterComment(self, comment):
        if self.regex.search(comment['body']):
            self.log_text = "Found Amazon referral link in comment"
            p(self.log_text + ":")
            p('http://reddit.com/r/{}/comments/{}/a/{}'.format(
                comment['subreddit'], comment['link_id'][3:], comment['id']))
            return True


class ShortUrl(Filter):
    def __init__(self):
        Filter.__init__(self)
        self.regex = re.compile(
            r'''(?:bit\.ly|goo\.gl|adf\.ly|is\.gd|t\.co|tinyurl\.com|j\.mp|'''
            r'''tiny\.cc|soc\.li|ultrafiles\.net|linkbucks\.com|lnk\.co|qvvo\.com|ht\.ly|'''
            r'''pulse\.me)/''', re.I)

    def filterSubmission(self, submission):
        if self.regex.search(submission['title']) or\
            self.regex.search(submission['selftext']) or\
                self.regex.search(submission['url']):
            link = 'http://reddit.com/r/{}/comments/{}/'.format(
                submission['subreddit'], submission['id'])
            self.log_text = "Found short url in submission"
            reason = "short urls are not allowed"
            self.comment = self.comment_template.format(
                sub=submission['subreddit'], reason=reason, link=link)
            p(self.log_text + ":")
            p(link)
            return True

    def filterComment(self, comment):
        if self.regex.search(comment['body']):
            self.comment = ''
            self.log_text = "Found short url in comment"
            p(self.log_text + ":")
            p('http://reddit.com/r/{}/comments/{}/a/{}'.format(
                comment['subreddit'], comment['link_id'][3:], comment['id']))
            return True


class Failed(Filter):
    def __init__(self):
        Filter.__init__(self)

    def filterSubmission(self, submission):
        link = 'http://reddit.com/r/{}/comments/{}/'.format(
            submission['subreddit'], submission['id'])
        if submission['domain'].startswith('['):
            self.log_text = "Found submission with formatting in the url"
            self.comment = (
                "You've seemed to try to use markdown or other markup in the url field"
                " when you made this submission. Markdown formatting is only for self text and comm"
                "enting; other formatting code is invalid on reddit. When you make a link submissio"
                "n, please only enter the bare link in the url field.\n\nFeel free to try submitti"
                "ng again.")
            p(self.log_text + ":")
            p(link)
            return True
        elif '.' not in submission['domain']:
            self.log_text = "Found submission with invalid url"
            self.comment = (
                "The submission you've made does not have a valid url in it.  Please t"
                "ry resubmitting and make special attention to what you're typing/pasting in the ur"
                "l field.")
            p(self.log_text + ":")
            p(link)
            return True


class Minebook(Filter):
    def __init__(self):
        Filter.__init__(self)
        self.regex = re.compile(r'''minebook\.me''', re.I)
        self.action = 'spammed'

    def filterSubmission(self, submission):
        if self.regex.search(submission['title']) or\
            self.regex.search(submission['selftext']) or\
                submission['domain'] == 'minebook.me':
            self.log_text = "Found minebook in submission"
            p(self.log_text + ":")
            p('http://reddit.com/r/{}/comments/{}/'.format(
                submission['subreddit'], submission['id']))
            return True

    def filterComment(self, comment):
        if self.regex.search(comment['body']):
            self.log_text = "Found minebook in comment"
            p(self.log_text + ":")
            p('http://reddit.com/r/{}/comments/{}/a/{}'.format(
                comment['subreddit'], comment['link_id'][3:], comment['id']))


class SelfLinks(Filter):
    def __init__(self):
        Filter.__init__(self)
        self.regex = re.compile(r'''^(?:https?://|www\.)\S*$''')

    def filterSubmission(self, submission):
        if submission['selftext']:
            for i in submission['selftext'].split():
                if not self.regex.match(i):
                    break
            else:
                self.comment = (
                    "This submission has been removed automatically.  You appear to ha"
                    "ve only included links in your self-post with no explanatory text.  Please res"
                    "ubmit or edit your post accordingly.")
                self.log_text = "Found self-post that only contained links"
                p(self.log_text + ":")
                p('http://reddit.com/r/{}/comments/{}/'.format(
                    submission['subreddit'], submission['id']))
                return True


class BadWords(Filter):
    def __init__(self):
        Filter.__init__(self)
        self.action = 'report'

    def filterComment(self, comment):
        badwords = ['gay', 'fag', 'cunt', 'nigger', 'retard', 'autis']
        if not comment['num_reports']:
            for word in badwords:
                if word in comment['body'].lower():
                    return True


class YoutubeSpam(Filter):
    def __init__(self):
        Filter.__init__(self)
        self.database = Database(DATABASEFILE)

    def _isVideo(self, submission):
        '''Returns video author name if this is a video'''
        if 'media' in submission:
            if submission['media'] is not None:
                if 'oembed' in submission['media']:
                    if 'author_name' in submission['media']['oembed']:
                        if submission['media']['oembed']['author_name'] is not None:
                            return submission['media']['oembed']['author_name'].replace(
                                ' ', '').lower()
        if 'user' in submission['url']:
            return re.findall(r'''user/(.*)[?/]''', submission['url'])[0]

    def _checkProfile(self, user):
        '''Returns the percentage of things that the user only contributed to themselves.
        ie: submitting and only commenting on their content.  Currently, the criteria is:
            * linking to videos of the same author (which implies it is their account)
            * commenting on your own submissions (not just videos)
        these all will count against the user and an overall score will be returned.  Also, we only
        check against the last 100 items on the user's profile.'''

        try:
            with self.opener.open(
                'http://www.reddit.com/user/{}/comments/.json?limit=100&sort=new'.format(
                    user)) as w:
                comments = json.loads(w.read().decode('utf-8'))
                comments = comments['data']['children']
                time.sleep(2)
            with self.opener.open(
                'http://www.reddit.com/user/{}/submitted/.json?limit=100&sort=new'.format(
                    user)) as w:
                submitted = json.loads(w.read().decode('utf-8'))['data']['children']
                time.sleep(2)
        except urllib.error.HTTPError:
            # This is a hack to get around shadowbanned or deleted users
            p("Could not parse /u/{}, probably shadowbanned or deleted".format(user))
            return False
        video_count = defaultdict(lambda: 0)
        video_submissions = set()
        comments_on_self = 0
        for item in submitted:
            item = item['data']
            video_author = self._isVideo(item)
            if video_author:
                video_count[video_author] += 1
                video_submissions.add(item['name'])
        for item in comments:
            item = item['data']
            if item['link_id'] in video_submissions:
                comments_on_self += 1
        try:
            video_percent = max(
                [video_count[i] / sum(video_count.values()) for i in video_count])
        except ValueError:
            video_percent = 0
        if video_percent > .85 and sum(video_count.values()) >= 3:
            spammer_value = (sum(video_count.values()) + comments_on_self) / (len(
                comments) + len(submitted))
            if spammer_value > .85:
                return True

    def filterSubmission(self, submission):
        DAY = 24 * 60 * 60
        if submission['domain'] in ('m.youtube.com', 'youtube.com', 'youtu.be'):
            link = 'http://reddit.com/r/{}/comments/{}/'.format(
                submission['subreddit'], submission['id'])
            # check if we've already parsed this submission
            with self.database.open() as db:
                if submission['id'] in db['submissions']:
                    return False
                if submission['author'] in db['users']:
                    user = db['users'][submission['author']]
                else:
                    user = {'checked_last': 0, 'warned': False}

            if time.time() - user['checked_last'] > DAY:
                p("Checking profile of /u/{}".format(submission['author']), end='')
                user['checked_last'] = time.time()
                if self._checkProfile(submission['author']):
                    if user['warned']:
                        p("User was warned and still matches a spammer")
                        self.comment = ''
                        self.ban = True
                        self.nuke = True
                    else:
                        self.comment = (
                            """It looks like you might be skirting on the line with  """
                            """submitting your videos, so consider this a friendly warning/guidel"""
                            """ine:\n\nReddit has [guidelines as to what constitutes spam](/help/"""
                            """faq#Whatconstitutesspam).  To quote the page:\n\n* It's not strict"""
                            """ly forbidden to submit a link to a site that you own or otherwise """
                            """benefit from in some way, but you should sort of consider yourself"""
                            """ on thin ice. So please pay careful attention to the rest of these"""
                            """ bullet points.\n\n* If you spend more time submitting to reddit t"""
                            """han reading it, you're almost certainly a spammer.\n\n* If your co"""
                            """ntribution to Reddit consists mostly of submitting links to a site"""
                            """(s) that you own or otherwise benefit from in some way, and additi"""
                            """onally if you do not participate in discussion, or reply to people"""
                            """'s questions, regardless of how many upvotes your submissions get,"""
                            """ you are a spammer.\n\n* If people historically downvote your link"""
                            """s or ones similar to yours, and you feel the need to keep submitti"""
                            """ng them anyway, they're probably spam.\n\n* If people historically"""
                            """ upvote your links or ones like them -- and we're talking about re"""
                            """al people here, not sockpuppets or people you asked to go vote for"""
                            """ you -- congratulations! It's almost certainly not spam. But we're"""
                            """ serious about the "not people you asked to go vote for you" part."""
                            """\n\n* If nobody's submitted a link like yours before, give it a s"""
                            """hot. But don't flood the new queue; submit one or two times and se"""
                            """e what happens.\n\nFor right now, this is just a friendly message,"""
                            """ but here in /r/{0}, we take action against anyone that fits the a"""
                            """bove definition.\n\nIf you feel this was in error, feel free to [m"""
                            """essage the moderators](/message/compose/?to=/r/{0}&subject=Video%"""
                            """20Spam&message={1}).""".format(SUBREDDIT, link))
                        self.ban = False
                        self.nuke = False
                        self.log_text = "Found potential video spammer"
                        p(self.log_text + ":")
                        p("http://reddit.com/u/{}".format(submission['author']))
                        user['warned'] = True
                    with self.database.open() as db:
                        db['users'][submission['author']] = user
                        db['submissions'].append(submission['id'])
                    output = True
                else:
                    output = False
                with self.database.open() as db:
                    db['users'][submission['author']] = user
                    db['submissions'].append(submission['id'])
                return output


class AllCaps(Filter):
    def __init__(self):
        Filter.__init__(self)
        self.comment_template = (
            """Hey there, you seem to be yelling!  You don't need to be so l"""
            """oud with your title, your submission should be the one doing the talking for you. """
            """[Here's a link to resubmit with a more appropriate title]({link} 'click here to su"""
            """bmit').""")

    def filterSubmission(self, submission):
        if len(submission['title']) > 10:
            if len(re.findall(
                r'''[A-Z]''', submission['title'])) / len(re.findall(
                    r'''[a-zA-Z]''', submission['title'])) > .7:
                self.log_text = "Found submission with all-caps title"
                p(self.log_text + ":")
                p('http://reddit.com/r/{}/comments/{}/'.format(
                    submission['subreddit'], submission['id']))
                params = {'title': submission['title'].title(), 'resubmit': True}
                if submission['selftext']:
                    params['text'] = submission['selftext']
                else:
                    params['url'] = submission['url']
                self.comment = self.comment_template.format(
                    link='/r/{}/submit?{}'.format(submission['subreddit'], urlencode(params)))
                return True


class BannedSubs(Filter):
    def __init__(self):
        Filter.__init__(self)
        self.action = 'spammed'

    def filterComment(self, comment):
        if not comment['num_reports']:
            for word in BANNEDSUBS:
                if word in comment['body'].lower():
                    return True


class Meme(Filter):
    def __init__(self):
        Filter.__init__(self)
        self.comment_template = self.comment_template + (
            "\n\nYou are free to [resubmit to a more appropriate subreddit]({resubmit} 'click here "
            "to resubmit')")
        self.meme_sites = (
            'memecreator.org', 'memegenerator.net', 'quickmeme.com', 'qkme.me', 'mememaker.net',
            'knowyourmeme.com', 'weknowmemes.com')

    def filterSubmission(self, submission):
        if 'reddit.com' not in submission['url']:
            link = 'http://reddit.com/r/{}/comments/{}/'.format(
                submission['subreddit'], submission['id'])
            for i in self.meme_sites:
                if i in submission['url']:
                    params = {
                        'title': submission['title'].title(), 'resubmit': True,
                        'url': submission['url']}
                    resubmit = '/r/{}/submit?{}'.format('memecraft', urlencode(params))
                    reason = "meme submissions are not allowed"
                    self.comment = self.comment_template.format(
                        sub=submission['subreddit'], reason=reason, link=link, resubmit=resubmit)
                    self.action = 'spammed'
                    self.log_text = "Found meme submission"
                    p(self.log_text + ":")
                    p(link)
                    return True
            else:
                if 'meme' in submission['url']:
                    self.comment = ""
                    self.action = 'report'
                    self.log_text = "Found suspected meme submission"
                    p(self.log_text + ":")
                    p(link)
                    return True


class InaneTitle(Filter):
    def __init__(self):
        Filter.__init__(self)
        self.regex = re.compile(
            r'''you(?:'?re|r| are) drunk|minecraft logic|what does (?:/r/minecraft|reddit) think''',
            re.I)
        self.comment_template = (
            """Hey there, you seem to be using an inane title!  You can pro"""
            """bably think of something a little more original than that.  [Here's a link to resu"""
            """bmit to help you on your way](/r/{sub}/submit?{params} 'click here to submit').  H"""
            """ere's what was in your title that has been deemed inane:\n\n* {matches}""")

    def filterSubmission(self, submission):
        matches = self.regex.findall(submission['title'])
        if matches:
            matches="\n\n* ".join(matches)
            self.log_text = "Found submsission with inane title"
            p(self.log_text + ":")
            p('http://reddit.com/r/{}/comments/{}/'.format(
                submission['subreddit'], submission['id']))
            params = {'resubmit': True}
            if submission['selftext']:
                    params['text'] = submission['selftext']
            else:
                params['url'] = submission['url']
            self.comment = self.comment_template.format(
                sub=submission['subreddit'], params=urlencode(params), matches=matches)
            return True


def main():
    sleep_time = 60 * 3
    r = Reddit(USERNAME, PASSWORD)
    last_status = None
    processed = {'ids': [], 'authors': []}
    p('Started monitoring submissions on /r/{}.'.format(SUBREDDIT))

    filters = [
        Suggestion(), Fixed(), ServerAd(), FreeMinecraft(), AmazonReferral(), ShortUrl(),
        Failed(), Minebook(), SelfLinks(), BadWords(), YoutubeSpam(), AllCaps(), BannedSubs(),
        Meme(), InaneTitle()]

    # main loop
    while True:
        p('Getting feed...', end='')
        new_listing = r.get('http://reddit.com/r/{}/new/.json?sort=new'.format(SUBREDDIT))
        modqueue_listing = r.get('http://reddit.com/r/{}/about/modqueue.json'.format(SUBREDDIT))
        comments_listing = r.get('http://reddit.com/r/{}/comments/.json'.format(SUBREDDIT))
        feed = []
        status = mojangStatus()
        p('Checking Mojang servers...', end='')
        if status:
            if last_status:
                if status != last_status:
                    p('Mojang server status changed, updating sidebar...', end='')
                    r.sidebar(SUBREDDIT, status)
            last_status = status

        for i in (new_listing, modqueue_listing, comments_listing):
            feed.extend(i['data']['children'])
        for item in feed:
            item = item['data']
            if item['id'] not in processed['ids']:
                p('Processing {}'.format(item['id']), end="")
                for f in filters:
                    processed['ids'].append(item['id'])
                    # I know using 'is not True' isn't the 'right' way, but reddit's api is weird
                    # here and I wanted to explicitly show it
                    if item['banned_by'] is not True:
                        break
                    if item['author'] in (USERNAME, 'tweet_poster'):
                        break
                    if item['approved_by']:
                        break
                    if f.runFilter(item):
                        if f.nuke:
                            r.nuke(item, f.action)
                        if f.comment:
                            comment = {'thing_id': item['name'], 'text': f.comment}
                            submission = r.post(
                                'http://www.reddit.com/api/comment',
                                comment)['json']['data']['things'][0]['data']['id']
                            distinguish = {'id': submission, 'executed': 'distinguishing...'}
                            r.post('http://www.reddit.com/api/distinguish/yes', distinguish)
                        if f.tag:
                            r.rts(item['author'], tag=f.tag, subreddit=f.report_subreddit)
                        if f.ban and item['author'] not in processed['authors']:
                            p('Banning http://reddit.com/u/{}'.format(item['author']))
                            body = {
                                'action': 'add', 'type': 'banned', 'name': item['author'],
                                'id': '#banned', 'r': item['subreddit']}
                            r.post('http://www.reddit.com/api/friend', body)
                            processed['authors'].append(item['author'])
                        break
        for i in range(sleep_time):
            p('Next scan in {} seconds...'.format(sleep_time - i), end='')
            time.sleep(1)

if __name__ == '__main__':
    signal.signal(signal.SIGINT, sigint_handler)
    main()
