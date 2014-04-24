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
from collections import defaultdict
import random
from praw.handlers import MultiprocessHandler
import praw
import bz2
import operator

try:
    from credentials import *  # NOQA
except:
    USERNAME = 'botname'
    PASSWORD = 'botpass'
    USERAGENT = 'moderator-bot.py v4'
    SUBREDDIT = 'subtomonitor'
    HEADER_TAGS = {'start': '[](#heditstart)', 'stop': '[](#heditstop)'}
    SIDEBAR_TAGS = {'start': '[](#sbeditstart)', 'stop': '[](#sbeditstop)'}
    GREENTEXT = "[](#status_green '{} is online')"
    REDTEXT = "[](#status_red '{}' is offline')"
    BOTSUB = 'botprivatesub'
    LOGFILE = '/some/file/to/log/to.html'
    SERVERDOMAINS = 'http://example.com/server_domain_list.csv'
    DATABASEFILE = '/some/path'
    CACHEFILE = '/some/other/path'
    BANNEDSUBS = ['some', 'list']
    STATUS_JSON = 'http://somesite.com/some.json'
    VERSION_JSON = 'http://someothersite.com/some.json'
    IMGUR_CLIENT_ID = 'someid'


def p(data, end='\n', color_seed=None):
    if color_seed:
        random.seed(color_seed)
        color = '\033[0;3{}m'.format(random.randint(1, 6))
    else:
        color = ''
    print(time.strftime(
        '\r\033[K\033[2K[\033[31m%y\033[39m/\033[31m%m\033[39m/\033[31m%d'
        '\033[39m][\033[31m%H\033[39m:\033[31m%M\033[39m:\033[31m%S\033[39m] ')
        + color + data + '\033[39m', end=end)


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


def sidebarUpdater():
    '''Returns the status indicator for /r/Minecraft's sidebar'''
    opener = urllib.request.build_opener()
    opener.addheaders = [('User-agent', USERAGENT)]
    try:
        with opener.open(STATUS_JSON, timeout=30) as w:
            status = json.loads(w.read().decode('utf-8'))['report']
    except:
        return None
    try:
        with opener.open(VERSION_JSON, timeout=30) as w:
            version = json.loads(w.read().decode('utf-8'))['latest']
    except:
        return None
    text = []
    for i in ('website', 'login', 'session', 'skins', 'realms'):
        if status[i]['status'] == 'up':
            text.append("> ## [{server} is online.](#status_green '{server} - {status}')".format(
                server=i.title(), status=status[i]['title'].split()[0]))
        elif status[i]['status'] == 'problem':
            text.append(
                "> ## [{server} is having a problem.]"
                "(#status_green '{server} - {status}')".format(
                    server=i.title(), status=status[i]['title']))
        elif status[i]['status'] == 'down':
            text.append("> ## [{server} is offline.](#status_red '{server} - {status}')".format(
                server=i.title(), status=status[i]['title'].split('•')[0].strip()))
    status_text = '\n{}\n'.format('\n'.join(text))
    version_text = 'Stable: | Snapshot: {}'.format(version['release'], version['snapshot'])
    return status_text + version_text


def cache_url():
    """Url caching decorator.  For decorating class functions that take a single url as an arg
    and return the response."""

    def wrap(function):
        def new_function(*args):
            url = args[1]
            expire_after = args[0].cache_time
            try:
                with bz2.open(CACHEFILE, 'rt') as f:
                    d = json.loads(f.read())
            except (IOError, ValueError):
                d = dict()
            if not 'cache' in d:
                d['cache'] = dict()
            if url in d['cache']:
                output = d['cache'][url]
                expire_time = output['time'] + expire_after
                if expire_after == 0 or time.time() < expire_time:
                    return output['data']
                else:
                    del d['cache'][url]
            output = function(*args)
            if output:
                to_cache = {'time': time.time(), 'data': output}
                d['cache'][url] = to_cache
                with bz2.open(CACHEFILE, 'wt') as f:
                    f.write(json.dumps(d))
                return output
        return new_function
    return wrap


class Imgur(object):
    def __init__(self, client_id, cache_time=86400):
        self.opener = urllib.request.build_opener()
        self.opener.addheaders = [
            ('User-agent', USERAGENT),
            ('Authorization', 'Client-id {}'.format(client_id))]
        self.last_request = 0
        self.cache_time = cache_time

    @cache_url()
    def _request(self, url):
        try:
            since_last = time.time() - self.last_request
            if not since_last >= 2:
                time.sleep(2 - since_last)
            with self.opener.open(url, timeout=30) as w:
                imgur = w.read().decode('utf-8')
                imgur = json.loads(imgur)['data']
        except:
            self.last_request = 0
            return None

        if not 'error' in imgur:
            return imgur

    def _get_ids(self, url):
        """Turns a url into a set of imgur ids"""
        url = url.split('#')[0]
        if url.endswith('/'):
            url = url[:-1]
        if url.endswith('/all'):
            url = url[:-4]
        url = re.split(r'''imgur.com(?:/gallery|/a|/r/.*?)?/''', url)[1]
        ids = set(re.split(r''',|&''', url))
        return ids

    def _get(self, imgur_id, use_gallery, force_single=False):
        """Returns a list containing a dicts of titles/descriptions for images and galleries."""
        """We try the imgur_id as a album first, and if that fails we assume it's an individual"""
        """image.  If force_single is True, we skip the initial album try."""

        p("Checking imgur id {}...".format(imgur_id), end="", color_seed=imgur_id)

        if use_gallery:
            urls = {
                'album': 'https://api.imgur.com/3/gallery/album/{}.json',
                'image': 'https://api.imgur.com/3/gallery/image/{}.json'}
        else:
            urls = {
                'album': 'https://api.imgur.com/3/album/{}.json',
                'image': 'https://api.imgur.com/3/image/{}.json'}

        if not force_single:
            output = list()
            imgur = self._request(urls['album'].format(imgur_id))
            if imgur:
                output.append({'title': imgur['title'], 'description': imgur['description']})
                for i in imgur['images']:
                    output.append({'title': i['title'], 'description': i['description']})
                return output

        imgur = self._request(urls['image'].format(imgur_id))

        if imgur:
            return [{'title': imgur['title'], 'description': imgur['description']}]

    def get(self, url):
        """Returns a list of dicts of the title/description of images/galleries"""

        output = list()
        ids = self._get_ids(url)

        if 'gallery' in url.lower():
            use_g = True
        else:
            use_g = False

        # we can assume that if we have a list, that they're all individual images
        if len(ids) > 1:
            for i in ids:
                imgur = self._get(i, use_g)
                if imgur:
                    output.extend(imgur)
        else:
            imgur = self._get(ids.pop(), use_g)
            if imgur:
                output = imgur

        return output


class Youtube(object):
    def __init__(self, cache_time=0):
        self.opener = urllib.request.build_opener()
        self.opener.addheaders = [('User-agent', USERAGENT)]
        self.last_request = 0
        self.cache_time = cache_time

    @cache_url()
    def _request(self, url):
        try:
            since_last = time.time() - self.last_request
            if not since_last >= 2:
                time.sleep(2 - since_last)
            with self.opener.open(url, timeout=30) as w:
                youtube = w.read().decode('utf-8')
                yt_json = json.loads(youtube)
        except:
            self.last_request = time.time()
            return None

        if not 'errors' in yt_json:
            return yt_json['entry']

    def _get_id(self, url):
        # regex via: http://stackoverflow.com/questions/3392993/php-regex-to-get-youtube-video-id
        regex = re.compile(
            r'''(?<=(?:v|i)=)[a-zA-Z0-9-]+(?=&)|(?<=(?:v|i)\/)[^&\n]+|(?<=embed\/)[^"&\n]+|'''
            r'''(?<=(?:v|i)=)[^&\n]+|(?<=youtu.be\/)[^&\n]+''', re.I)
        yt_id = regex.findall(
            url.replace('%3D', '=').replace('%26', '&').replace('%2F', '?').replace('&amp;', '&'))

        if yt_id:
            # temp fix:
            yt_id = yt_id[0].split('#')[0]
            yt_id = yt_id.split('?')[0]
            return yt_id

    def _get(self, url):
        """Decides if we're grabbing video info or a profile."""
        urls = {
            'profile': 'http://gdata.youtube.com/feeds/api/users/{}?v=2&alt=json',
            'video': 'http://gdata.youtube.com/feeds/api/videos/{}?v=2&alt=json'}

        yt_id = self._get_id(url)

        if yt_id:
            return self._request(urls['video'].format(yt_id))
        else:
            username = re.findall(r'''(?i)\.com\/(?:user\/|channel\/)?(.*?)(?:\/|\?|$)''', url)
            if username:
                return self._request(urls['profile'].format(username[0]))

    def get_author(self, url):
        """Returns the author id of the youtube url"""
        output = self._get(url)
        if output:
            # There has to be a reason for the list in there...
            return output['author'][0]['yt$userId']['$t']

    def get_info(self, url):
        """Returns the title and description of a video."""
        output = self._get(url)
        if output:
            if 'media$group' in output:
                title = output['title']['$t']
                description = output['media$group']['media$description']['$t']
                return {'title': title, 'description': description}

    def is_video(self, url):
        if self._get_id(url) is not None:
            return True
        else:
            return False


class Filter(object):
    """Base filter class"""
    def __init__(self):
        self.regex = None
        self.comment_template = (
            "##This submission has been removed automatically.\nAccording to our [subreddit rules]("
            "/r/{sub}/wiki/rules/) {reason}.  If you feel this was in error, please [message the mo"
            "derators](/message/compose/?to=/r/{sub}&subject=Removal%20Dispute&message={link}).  If"
            " this submission was removed in error, do not delete it.  The moderators will fix this"
            " submission.")
        self.comment = ""
        self.tag = ""
        self.action = 'remove'
        self.log_text = ""
        self.ban = False
        self.report_subreddit = None
        self.nuke = True
        self.reddit = None

    def filterComment(self, comment):
        raise NotImplementedError

    def filterSubmission(self, submission):
        raise NotImplementedError

    def runFilter(self, post):
        if 'title' in vars(post):
            try:
                if self.filterSubmission(post):
                    if self.log_text:
                        logToDisk(self.log_text)
                    return True
            except NotImplementedError:
                pass
        elif 'body' in vars(post):
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
        if self.regex.search(submission.title):
            link = 'http://reddit.com/r/{}/comments/{}/'.format(
                submission.subreddit, submission.id)

            if submission.domain != 'self.{}'.format(submission.subreddit):
                reason = "suggestions must be self-post only"
                self.log_text = "Found [Suggestion] submission that is not a self post"
                self.comment = self.comment_template.format(
                    sub=submission.subreddit, reason=reason, link=link)
                p(self.log_text + ":")
                p(link, color_seed=submission.name)
                return True
            elif not submission.selftext:
                self.log_text = "Found [Suggestion] submission that has no self text"
                reason = (
                    "suggestion posts must have a description along with them, which is something y"
                    "ou cannot convey with only a title")
                self.comment = self.comment_template.format(
                    sub=submission.subreddit, reason=reason, link=link)
                p(self.log_text + ":")
                p(link, color_seed=submission.name)
                return True


class Fixed(Filter):
    def __init__(self):
        Filter.__init__(self)
        self.regex = re.compile(
            r'''[\[|<\({\*]fixed[\]|>\):}\*]|'''
            r'''i(?:'?ll)? see you'?re?,? .*? and (?:i(?:'?ll)? )?raise you''', re.I)
        self.log_text = "Found [Fixed] submission"

    def filterSubmission(self, submission):
        if self.regex.search(submission.title):
            link = 'http://reddit.com/r/{}/comments/{}/'.format(
                submission.subreddit, submission.id)
            reason = "[Fixed] submissions are not allowed"
            self.comment = self.comment_template.format(
                sub=submission.subreddit, reason=reason, link=link)
            p(self.log_text + ":")
            p(link, color_seed=submission.name)
            return True


class ServerAd(Filter):
    def __init__(self, reddit, imgur, youtube):
        self.last_update = 0
        self.domain_list = []
        Filter.__init__(self)
        self.reddit = reddit
        self.imgur = imgur
        self.y = youtube
        self.tag = "[Server Spam]"
        self.regex = re.compile(
            r'''(?:^|\s|ip(?:=|:)|\*)(\d{1,3}(?:\.\d{1,3}){3})\.?(?:\s|$|:|\*|!|\.|,|;|\?)''', re.I)

    def _update_list(self):
        if (time.time() - self.last_update) >= 1800:
            self.last_update = time.time()
            p('Updating domain blacklist...', end='')
            blacklist = self.reddit.get_wiki_page(SUBREDDIT, 'server_blacklist')
            blacklist = blacklist.content_md
            domain_list = [
                i.replace(' ', '') for i in re.split(r'''[\r\n]*''', blacklist) if not
                i.startswith("//")]
            domain_list = [i for i in domain_list if i]
            if len(self.domain_list) < len(domain_list):
                p('Found {} new domains in online blacklist.'.format(
                    len(domain_list) - len(self.domain_list)))
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
                ips = self.regex.findall(text)
                for ip in ips:
                    if ip:
                        split_ip = [int(i) for i in ip.split('.')]
                        if split_ip[0] == 10:
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
                    else:
                        return False
            except ValueError:
                return False

    def _imgur_check(self, url):
        '''Takes a imgur url and returns True if a server ad is found in the title or description'''
        url = url.replace('&amp;', '&')
        image_list = self.imgur.get(url)
        for i in image_list:
            if i['description']:
                if self._server_in(i['description']):
                    return True
            if i['title']:
                if self._server_in(i['title']):
                    return True
        return False

    def _planet_minecraft_check(self, url):
        '''Takes a planet minecraft url and returns True if a server ad is found in its
        description'''
        url = url.replace('&amp', '&')
        opener = urllib.request.build_opener()
        opener.addheaders = [('User-agent', USERAGENT)]
        try:
            with opener.open(url, timeout=30) as w:
                page = w.read().lower().replace('\n', '')
                page = re.findall(r'''r-text-block">(.*?)</div>''', page)[0]
        except:
            return None
        if page:
            if self._server_in(page):
                return True

    def filterSubmission(self, submission):
        self.comment = ''
        reason = "server advertisements are not allowed; please use /r/mcservers"
        if self._server_in(submission.title) or\
            self._server_in(submission.selftext) or\
                self._server_in(submission.url[7:]):
            self.log_text = "Found server advertisement in submission"
            link = 'http://reddit.com/r/{}/comments/{}/'.format(
                submission.subreddit, submission.id)
            self.comment = self.comment_template.format(
                sub=submission.subreddit, reason=reason, link=link)
            p(self.log_text + ":")
            p(link, color_seed=submission.name)
            return True
        elif submission.domain == 'imgur.com':
            if self._imgur_check(submission.url):
                self.log_text = "Found server advertisement in submission"
                link = 'http://reddit.com/r/{}/comments/{}/'.format(
                    submission.subreddit, submission.id)
                self.comment = self.comment_template.format(
                    sub=submission.subreddit, reason=reason, link=link)
                p(self.log_text + ":")
                p(link)
                return True
        elif submission.domain in ('m.youtube.com', 'youtube.com', 'youtu.be'):
            yt = self.y.get_info(submission.url)
            if yt:
                if self._server_in(yt['title']) or self._server_in(yt['description']):
                    self.log_text = "Found server advertisement in submission"
                    link = 'http://reddit.com/r/{}/comments/{}/'.format(
                        submission.subreddit, submission.id)
                    self.comment = self.comment_template.format(
                        sub=submission.subreddit, reason=reason, link=link)
                    p(self.log_text + ":")
                    p(link, color_seed=submission.name)
                    return True
        elif submission.domain == 'planetminecraft.com':
            if self._planet_minecraft_check(submission.url):
                self.log_text = "Found server advertisement in submission"
                link = 'http://reddit.com/r/{}/comments/{}/'.format(
                    submission.subreddit, submission.id)
                self.comment = self.comment_template.format(
                    sub=submission.subreddit, reason=reason, link=link)
                p(self.log_text + ":")
                p(link)
                return True

    def filterComment(self, comment):
        if self._server_in(comment.body):
            self.comment = ''
            self.log_text = "Found server advertisement in comment"
            p(self.log_text + ":")
            p('http://reddit.com/r/{}/comments/{}/a/{}'.format(
                comment.subreddit.display_name, comment.link_id[3:], comment.id),
                color_seed=comment.link_id)
            return True


class FreeMinecraft(Filter):
    def __init__(self):
        Filter.__init__(self)
        self.regex = re.compile(
            r'''(?:(?:(free|cracked)?-?minecraft-?(install|get|'''
            r'''(?:gift-?)?codes?(?:-?gen(?:erator)?)?|rewards?|acc(?:t|ount)s?(?:free)?|now|'''
            r'''forever)?(?:\.blogspot)?)|(epicfreeprizes)|(freemspointsforever)|(litekoin)|'''
            r'''(ccincc)|(steampowers)|(cardcodes))'''
            r'''[\[\(\{]*?(?:\.|dot|\s)[\]\)\}]*?(?:me|info|com|net|org|ru|co\.uk|us)''',
            re.I)
        self.action = 'spammed'
        self.ban = True

    def empty(self, thing):
        if thing == ('', '', '', '', '', '', '', ''):
            return True
        elif isinstance(thing, list):
            for i in thing:
                if i != ('', '', '', '', '', '', '', ''):
                    return False
            else:
                return True
        elif not thing:
            return False
        else:
            return True

    def filterSubmission(self, submission):
        for i in (submission.title, submission.selftext, submission.url):
            result = self.regex.findall(i)
            if result:
                if not self.empty(result):
                    link = 'http://reddit.com/r/{}/comments/{}/'.format(
                        submission.subreddit, submission.id)
                    self.log_text = "Found free Minecraft link in submission"
                    reason = "free minecraft links are not allowed"
                    self.comment = self.comment_template.format(
                        sub=submission.subreddit, reason=reason, link=link)
                    p(self.log_text + ":")
                    p(link, color_seed=submission.name)
                    return True

    def filterComment(self, comment):
        result = self.regex.findall(comment.body)
        if result:
            for i in result:
                if not self.empty(result):
                    self.comment = ''
                    self.log_text = "Found free minecraft link in comment"
                    p(self.log_text + ":")
                    p('http://reddit.com/r/{}/comments/{}/a/{}'.format(
                        comment.subreddit.display_name, comment.link_id[3:], comment.id),
                        color_seed=comment.link_id)
                    return True


class AmazonReferral(Filter):
    def __init__(self):
        Filter.__init__(self)
        self.regex = re.compile(
            r'''amazon\.(?:at|fr|com|ca|cn|de|es|it|co\.(?:jp|uk)).*?tag=[^&]*?-\d+''', re.I)
        self.action = 'spammed'

    def filterSubmission(self, submission):
        if self.regex.search(submission.title) or\
            self.regex.search(submission.selftext) or\
                self.regex.search(submission.url):
            self.log_text = "Found Amazon referral link in submission"
            link = 'http://reddit.com/r/{}/comments/{}/'.format(
                submission.subreddit, submission.id)
            p(self.log_text + ":")
            p(link, color_seed=submission.name)
            return True

    def filterComment(self, comment):
        if self.regex.search(comment.body):
            self.log_text = "Found Amazon referral link in comment"
            p(self.log_text + ":")
            p('http://reddit.com/r/{}/comments/{}/a/{}'.format(
                comment.subreddit.display_name, comment.link_id[3:], comment.id),
                color_seed=comment.link_id)
            return True


class ShortUrl(Filter):
    def __init__(self):
        Filter.__init__(self)
        self.regex = re.compile(
            r'''(?:bit\.ly|goo\.gl|adf\.ly|is\.gd|(?<!reddi)(?:t\.co)(?!m|\.uk)|tinyurl\.com|'''
            r'''j\.mp|linkbitty\.com|tiny\.cc|soc\.li|ultrafiles\.net|linkbucks\.com|lnk\.co'''
            r'''|qvvo\.com|ht\.ly|pulse\.me|lmgtfy\.com|\.tk|skroc\.pl|ufa\.lt|alturl\.com|'''
            r'''awe\.sm|q\.gs|lat\.li)''',
            re.I)

    def filterSubmission(self, submission):
        if self.regex.search(submission.title) or\
            self.regex.search(submission.selftext) or\
                self.regex.search(submission.url):
            link = 'http://reddit.com/r/{}/comments/{}/'.format(
                submission.subreddit, submission.id)
            self.log_text = "Found short url in submission"
            reason = "short urls are not allowed"
            self.comment = self.comment_template.format(
                sub=submission.subreddit, reason=reason, link=link)
            p(self.log_text + ":")
            p(link, color_seed=submission.name)
            return True

    def filterComment(self, comment):
        if self.regex.search(comment.body):
            self.comment = ''
            self.log_text = "Found short url in comment"
            p(self.log_text + ":")
            p('http://reddit.com/r/{}/comments/{}/a/{}'.format(
                comment.subreddit.display_name, comment.link_id[3:], comment.id),
                color_seed=comment.link_id)
            return True


class Failed(Filter):
    def __init__(self):
        Filter.__init__(self)

    def filterSubmission(self, submission):
        link = 'http://reddit.com/r/{}/comments/{}/'.format(
            submission.subreddit, submission.id)
        if submission.domain.startswith('['):
            self.log_text = "Found submission with formatting in the url"
            self.comment = (
                "You've seemed to try to use markdown or other markup in the url field"
                " when you made this submission. Markdown formatting is only for self text and comm"
                "enting; other formatting code is invalid on reddit. When you make a link submissio"
                "n, please only enter the bare link in the url field.\n\nFeel free to try submitti"
                "ng again.")
            p(self.log_text + ":")
            p(link, color_seed=submission.name)
            return True
        elif '.' not in submission.domain:
            self.log_text = "Found submission with invalid url"
            self.comment = (
                "The submission you've made does not have a valid url in it.  Please t"
                "ry resubmitting and pay special attention to what you're typing/pasting in the ur"
                "l field.")
            p(self.log_text + ":")
            p(link, color_seed=submission.name)
            return True


class Minebook(Filter):
    def __init__(self):
        Filter.__init__(self)
        self.regex = re.compile(r'''minebook\.me''', re.I)
        self.action = 'spammed'

    def filterSubmission(self, submission):
        if self.regex.search(submission.title) or\
            self.regex.search(submission.selftext) or\
                submission.domain == 'minebook.me':
            self.log_text = "Found minebook in submission"
            p(self.log_text + ":")
            p('http://reddit.com/r/{}/comments/{}/'.format(
                submission.subreddit, submission.id), color_seed=submission.name)
            return True

    def filterComment(self, comment):
        if self.regex.search(comment.body):
            self.log_text = "Found minebook in comment"
            p(self.log_text + ":")
            p('http://reddit.com/r/{}/comments/{}/a/{}'.format(
                comment.subreddit.display_name, comment.link_id[3:], comment.id),
                color_seed=comment.name)


class SelfLinks(Filter):
    def __init__(self):
        Filter.__init__(self)
        self.regex = re.compile(r'''^(?:https?://|www\.)\S*$''')

    def filterSubmission(self, submission):
        if submission.selftext:
            for i in submission.selftext.split():
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
                    submission.subreddit, submission.id), color_seed=submission.name)
                return True


class BadWords(Filter):
    def __init__(self):
        Filter.__init__(self)
        self.action = 'report'
        self.badwords = [
            'gay', 'fag', 'fgt', 'fggot', 'cunt', 'slut', 'nigger', 'nigga', 'retard', 'autis',
            'unedditreddit', 'subredditdrama', 'srd']

    def filterSubmission(self, submission):
        if not submission.num_reports:
            for word in self.badwords:
                if word in submission.selftext.lower() or word in submission.title.lower():
                    self.log_text = "Found submission for mod review"
                    p(self.log_text + ":", end="")
                    p('http://reddit.com/r/{}/comments/{}/'.format(
                        submission.subreddit, submission.id), color_seed=submission.name,
                        end="")
                    return True

    def filterComment(self, comment):
        if not comment.num_reports:
            for word in self.badwords:
                if word in comment.body.lower():
                    self.log_text = "Found comment for mod review"
                    p(self.log_text + ":", end="")
                    p('http://reddit.com/r/{}/comments/{}/a/{}'.format(
                        comment.subreddit.display_name, comment.link_id[3:], comment.id),
                        color_seed=comment.link_id, end="")
                    return True


class YoutubeSpam(Filter):
    def __init__(self, reddit, youtube):
        Filter.__init__(self)
        self.tag = "[Youtube Spam]"
        self.reddit = reddit
        self.y = youtube

    def _isVideo(self, submission):
        '''Returns video author name if this is a video'''
        if submission.domain in ('m.youtube.com', 'youtube.com', 'youtu.be'):
            return self.y.get_author(submission.url)

    def _checkProfile(self, submission):
        '''Returns the percentage of things that the user only contributed to themselves.
        ie: submitting and only commenting on their content.  Currently, the criteria is:
            * linking to videos of the same author (which implies it is their account)
            * commenting on your own submissions (not just videos)
        these all will count against the user and an overall score will be returned.  Also, we only
        check against the last 100 items on the user's profile.'''

        try:
            start_time = time.time() - (60 * 60 * 24 * 30 * 6)  # ~six months
            redditor = self.reddit.get_redditor(submission.author.name)
            comments = [i for i in redditor.get_comments(limit=100) if i.created_utc > start_time]
            submitted = [i for i in redditor.get_submitted(limit=100) if i.created_utc > start_time]
        except urllib.error.HTTPError:
            # This is a hack to get around shadowbanned or deleted users
            p("Could not parse /u/{}, probably shadowbanned or deleted".format(user))
            return False
        video_count = defaultdict(lambda: 0)
        video_submissions = set()
        comments_on_self = 0
        initial_author = self._isVideo(submission)
        for item in submitted:
            video_author = self._isVideo(item)
            if video_author:
                video_count[video_author] += 1
                video_submissions.add(item.name)
        most_submitted_author = max(video_count.items(), key=operator.itemgetter(1))[0]
        for item in comments:
            if item.link_id in video_submissions:
                comments_on_self += 1
        try:
            video_percent = max(
                [video_count[i] / sum(video_count.values()) for i in video_count])
        except ValueError:
            video_percent = 0
        if video_percent > .85 and sum(video_count.values()) >= 3:
            spammer_value = (sum(video_count.values()) + comments_on_self) / (len(
                comments) + len(submitted))
            if spammer_value > .85 and initial_author == most_submitted_author:
                return True

    def filterSubmission(self, submission):
        self.report_subreddit = None
        DAY = 24 * 60 * 60
        if submission.domain in ('m.youtube.com', 'youtube.com', 'youtu.be'):
            link = 'http://reddit.com/r/{}/comments/{}/'.format(
                submission.subreddit, submission.id)
            # check if we've already parsed this submission
            try:
                with bz2.open(DATABASEFILE, 'rt') as db:
                    db = json.loads(db.read())
            except IOError:
                db = dict()
                db['users'] = dict()
                db['submissions'] = list()

            if submission.id in db['submissions']:
                return False
            if submission.author.name in db['users']:
                user = db['users'][submission.author.name]
            else:
                user = {'checked_last': 0, 'warned': False, 'banned': False}

            if time.time() - user['checked_last'] > DAY:
                p("Checking profile of /u/{}".format(submission.author.name), end='')
                user['checked_last'] = time.time()
                if self._checkProfile(submission):
                    if user['warned']:
                        self.log_text = "Confirmed video spammer"
                        p(self.log_text + ":")
                        self.comment = ''
                        self.report_subreddit = 'reportthespammers'
                        self.ban = True
                        self.nuke = True
                        user['banned'] = True
                    else:
                        self.comment = (
                            """Hello, /u/{user}, it looks like you might be skirting on the line """
                            """with submitting your videos, so consider this a friendly warning/g"""
                            """uideline:\n\nReddit has [guidelines as to what constitutes spam](/"""
                            """wiki/faq#wiki_what_constitutes_spam.3F).  To quote the page:\n\n* """
                            """It's not strictly forbidden to submit a link to a site that you ow"""
                            """n or otherwise benefit from in some way, but you should sort of co"""
                            """nsider yourself on thin ice. So please pay careful attention to th"""
                            """e rest of these bullet points.\n\n* If you spend more time submitt"""
                            """ing to reddit than reading it, you're almost certainly a spammer. """
                            """\n\n* If your contribution to Reddit consists mostly of submitting"""
                            """ links to a site(s) that you own or otherwise benefit from in some"""
                            """ way, and additionally if you do not participate in discussion, or"""
                            """ reply to people's questions, regardless of how many upvotes your """
                            """submissions get, you are a spammer.\n\n* If people historically do"""
                            """wnvote your links or ones similar to yours, and you feel the need """
                            """to keep submitting them anyway, they're probably spam.\n\n* If peo"""
                            """ple historically upvote your links or ones like them -- and we're """
                            """talking about real people here, not sockpuppets or people you aske"""
                            """d to go vote for you -- congratulations! It's almost certainly not"""
                            """ spam. But we're serious about the "not people you asked to go vot"""
                            """e for you" part.\n\n* If nobody's submitted a link like yours befo"""
                            """re, give it a shot. But don't flood the new queue; submit one or t"""
                            """wo times and see what happens.\n\nFor right now, this is just a fr"""
                            """iendly message, but here in /r/{sub}, we take action against anyon"""
                            """e that fits the above definition.\n\nIf you feel this was in error"""
                            """, feel free to [message the moderators](/message/compose/?to=/r/"""
                            """{sub}&subject=Video%20Spam&message={link}).""".format(
                                user=submission.author.name, sub=SUBREDDIT, link=link))
                        self.ban = False
                        self.nuke = False
                        self.log_text = "Found potential video spammer"
                        p(self.log_text + ":")
                        p("http://reddit.com/u/{}".format(submission.author.name),
                            color_seed=submission.author.name)
                        user['warned'] = True
                    output = True
                else:
                    output = False
                db['users'][submission.author.name] = user
                db['submissions'].append(submission.id)
                with bz2.open(DATABASEFILE, 'wt') as f:
                    f.write(json.dumps(db))
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
        title = re.findall(r'''[a-zA-Z]''', submission.title)
        title_caps = re.findall(r'''[A-Z]''', submission.title)
        if len(title) > 10:
            if len(title_caps) / len(title) > .7:
                self.log_text = "Found submission with all-caps title"
                p(self.log_text + ":")
                p('http://reddit.com/r/{}/comments/{}/'.format(
                    submission.subreddit, submission.id), color_seed=submission.name)
                params = {'title': submission.title.title(), 'resubmit': True}
                if submission.selftext:
                    params['text'] = submission.selftext
                else:
                    params['url'] = submission.url
                self.comment = self.comment_template.format(
                    link='/r/{}/submit?{}'.format(submission.subreddit, urlencode(params)))
                return True


class BannedSubs(Filter):
    def __init__(self):
        Filter.__init__(self)
        self.action = 'spammed'

    def filterComment(self, comment):
        if not comment.num_reports:
            for word in BANNEDSUBS:
                if word in comment.body.lower():
                    return True


class Meme(Filter):
    def __init__(self):
        Filter.__init__(self)
        self.comment_template = self.comment_template + (
            "\n\nYou are free to [resubmit to a more appropriate subreddit]({resubmit} 'click here "
            "to resubmit').")
        self.meme_sites = (
            'memecreator.org', 'memegenerator.net', 'quickmeme.com', 'qkme.me', 'mememaker.net',
            'knowyourmeme.com', 'weknowmemes.com', 'elol.com', 'memecdn.com', 'livememe.com',
            'memecenter.com', 'memegenerator.co', 'memedad.com', 'meme5.net')

    def filterSubmission(self, submission):
        link = 'http://reddit.com/r/{}/comments/{}/'.format(
            submission.subreddit, submission.id)
        selflink = "self.{}".format(submission.subreddit)
        for i in self.meme_sites:
            if submission.domain != selflink and i in submission.domain:
                params = {
                    'title': submission.title.title(), 'resubmit': True,
                    'url': submission.url}
                resubmit = '/r/{}/submit?{}'.format('memecraft', urlencode(params))
                reason = "meme submissions are not allowed"
                self.comment = self.comment_template.format(
                    sub=submission.subreddit, reason=reason, link=link, resubmit=resubmit)
                self.action = 'spammed'
                self.log_text = "Found meme submission"
                p(self.log_text + ":")
                p(link, color_seed=submission.name)
                return True
        else:
            if 'meme' in submission.url:
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
            r'''(?:you(?:'?re|r| are)|ur) drunk|minecraft logic|seems legit|'''
            r'''what does (?:/?r/minecraft|reddit) think|yo,? d(?:o|aw)g|'''
            r'''^\.*?(?:too )?(?:soon|late)[.!?]*?$|am i the only(?: one)?|you had one job|'''
            r'''^\S*ception$|when suddenly|first post|am i doin(?:g|')? (?:this|it) ri(?:te|ght)|'''
            r'''^day [0-9]+|cake ?day''',
            re.I)
        self.comment_template = (
            """Hey there, you seem to be using an inane title!  You can pro"""
            """bably think of something a little more original than that.  [Here's a link to resu"""
            """bmit to help you on your way](/r/{sub}/submit?{params} 'click here to submit').  H"""
            """ere's what was in your title that has been deemed inane:\n\n* {matches}""")

    def filterSubmission(self, submission):
        matches = self.regex.findall(submission.title.strip())
        if matches:
            matches = "\n\n* ".join(matches)
            self.log_text = "Found submission with inane title"
            p(self.log_text + ":")
            p('http://reddit.com/r/{}/comments/{}/'.format(
                submission.subreddit, submission.id), color_seed=submission.name)
            params = {'resubmit': True}
            if submission.selftext:
                params['text'] = submission.selftext
            else:
                params['url'] = submission.url
            self.comment = self.comment_template.format(
                sub=submission.subreddit, params=urlencode(params), matches=matches)
            return True


class SpamNBan(Filter):
    def __init__(self):
        Filter.__init__(self)
        self.regex = re.compile(
            r'''teslabots\.jimbo\.com|topminecraftworldseeds\.com|\/r\/mcgriefservers|'''
            r'''F2sTr6yNJ2A|instagc\.com|minecraftstack\.com''', re.I)
        self.ban = True
        self.action = 'spammed'

    def filterSubmission(self, submission):
        if self.regex.search(submission.title) or\
            self.regex.search(submission.selftext) or\
                self.regex.search(submission.url):
            self.log_text = "Found spam domain in submission"
            p(self.log_text + ":")
            p('http://reddit.com/r/{}/comments/{}/'.format(
                submission.subreddit, submission.id), color_seed=submission.name)
            return True

    def filterComment(self, comment):
        if self.regex.search(comment.body):
            self.log_text = "Found spam domain in comment"
            p(self.log_text + ":")
            p('http://reddit.com/r/{}/comments/{}/a/{}'.format(
                comment.subreddit.display_name, comment.link_id[3:], comment.id),
                color_seed=comment.link_id)
            return True


class FileDownload(Filter):
    def __init__(self):
        Filter.__init__(self)
        self.nuke = False
        self.comment = (
            """Hey, you seem to be linking directly to a file download site.  That's generally co"""
            """nsidered rude, so you might want to consider resubmitting with a screenshot and li"""
            """nking to the download in the comments.  Thanks!""")
        self.regex = re.compile(
            r'''filestube|4shared|mediafire|rapidshare|box\.net|hotfile|zshare|uploading\.com|'''
            r'''depositfiles|fileserve|zippyshare|esnips|filefactory|uploaded\.to|2shared|'''
            r'''fileswap|filehosting|assets\.minecraft\.net|\.jar$|\.exe$|\.zip$|\.tar\.gz$|'''
            r'''\.tar\bz2$|dl\.dropbox\.com''', re.I)

    def filterSubmission(self, submission):
        if self.regex.search(submission.url):
            if not submission.url.endswith(('.gif', '.png', '.jpg', '.jpeg')):
                return True


class ChunkError(Filter):
    def __init__(self):
        Filter.__init__(self)
        self.regex = re.compile(r'''terrain(?: generation)? (?:error|glitch)''')
        self.log_text = "Found chunk error/glitch submission"

    def filterSubmission(self, submission):
        if self.regex.search(submission.title):
            link = 'http://reddit.com/r/{}/comments/{}/'.format(
                submission.subreddit, submission.id)
            reason = "terrain generation glitches/errors submissions are not allowed"
            self.comment = self.comment_template.format(
                sub=submission.subreddit, reason=reason, link=link)
            p(self.log_text + ":")
            p(link, color_seed=submission.name)
            return True


class Facebook(Filter):
    def __init__(self):
        Filter.__init__(self)
        self.regex = re.compile(r'''facebook|fbcdn|picsimgesite''')
        self.log_text = "Found Facebook submission"

    def filterSubmission(self, submission):
        if self.regex.search(submission.domain):
            self.comment = (
                """Hey there! I removed your post since it linked to a facebook page, which can """
                """be traced back to a user profile. You should re-upload the picture somewhere e"""
                """lse like [imgur](http://imgur.com) or [minus](http://minus.com) and resubmit.""")
            p(self.log_text + ":")
            p('http://reddit.com/r/{}/comments/{}/'.format(
                submission.subreddit, submission.id), color_seed=submission.name)
            return True


class Reditr(Filter):
    def __init__(self):
        Filter.__init__(self)
        self.log_text = "Found Reditr app comment"
        self.action = 'spammed'

    def filterComment(self, comment):
        if '^Sent ^from ^[Reditr](http://reditr.com)' in comment.body:
            p(self.log_text + ":")
            p('http://reddit.com/r/{}/comments/{}/a/{}'.format(
                comment.subreddit.display_name, comment.link_id[3:], comment.id),
                color_seed=comment.link_id)
            return True


class YoutubeVideo(Filter):
    def __init__(self, youtube):
        Filter.__init__(self)
        self.log_text = "Found Youtube submission that is not a video"
        self.youtube = youtube
        self.comment_template = (
            """Hey there!  Your submission was removed because it contains a link to Youtube that"""
            """ is not a video or playlist, which is considered off-topic in /r/{sub}.  If you're"""
            """ going to submit a link to youtube it must be to a video.  Thanks!""")

    def filterSubmission(self, submission):
        if submission.domain in ('m.youtube.com', 'youtube.com', 'youtu.be'):
            if self.youtube.is_video(submission.url) is False:
                self.comment = self.comment_template.format(sub=submission.subreddit)
                p(self.log_text + ":")
                p('http://reddit.com/r/{}/comments/{}/'.format(
                    submission.subreddit, submission.id), color_seed=submission.name)
                return True


class Twitch(Filter):
    def __init__(self):
        Filter.__init__(self)
        self.log_text = "Found twitch.tv stream in submission"
        self.regex = re.compile(
            r'''(?:http://)?(?:www\.)?(?:[a-z]{2}\.)?twitch\.tv/[a-z0-9_-]+/[a-z]{1}/[0-9]+''',
            re.I)

    def filterSubmission(self, submission):
        if submission.domain.endswith('twitch.tv') and self.regex.match(submission.url) is None:
            link = 'http://reddit.com/r/{}/comments/{}/'.format(
                submission.subreddit, submission.id)
            reason = "direct links to twitch.tv streams are not allowed"
            self.comment = self.comment_template.format(
                sub=submission.subreddit, reason=reason, link=link)
            p(self.log_text + ":")
            p(link, color_seed=submission.name)
            return True


class BannedYoutubers(Filter):
    def __init__(self, reddit, youtube):
        self.last_update = 0
        Filter.__init__(self)
        self.reddit = reddit
        self.youtube = youtube
        self.action = 'spammed'

    def _update_list(self):
        if (time.time() - self.last_update) >= 1800:
            update_page = False
            added_ids = []
            self.youtube_list = []
            self.last_update = time.time()
            p('Updating youtube blacklist...', end='')
            blacklist = self.reddit.get_wiki_page(SUBREDDIT, 'youtube_blacklist')
            blacklist_text = blacklist.content_md
            youtube_list = [
                i.replace(' ', '') for i in re.split(r'''[\r\n]*''', blacklist_text) if not
                i.startswith("//")]
            youtube_list = [i for i in youtube_list if i]
            for youtuber in youtube_list:
                if youtuber.startswith('http'):
                    user_id = self.youtube.get_author(youtuber)
                    blacklist_text = blacklist_text.replace(youtuber, user_id)
                    self.youtube_list.append(user_id)
                    added_ids.append(user_id)
                    update_page = True
                else:
                    self.youtube_list.append(youtuber)
            if update_page:
                p('Updating youtube blacklist with {} new entries.'.format(
                    len(added_ids)))
                blacklist.edit(
                    content=blacklist_text, reason='Added ids: {}'.format(', '.join(added_ids)))

    def filterSubmission(self, submission):
        self._update_list()
        if submission.domain in ('m.youtube.com', 'youtube.com', 'youtu.be'):
            yt = self.youtube.get_author(submission.url)
            if yt:
                if yt in self.youtube_list:
                    link = 'http://reddit.com/r/{}/comments/{}/'.format(
                        submission.subreddit, submission.id)
                    self.log_text = "Found link to banned Youtuber in submission"
                    p(self.log_text + ":")
                    p(link, color_seed=submission.name)
                    return True


class Flair(Filter):
    def __init__(self, reddit):
        Filter.__init__(self)
        self.reddit = reddit
        self.nuke = False

    def filterSubmission(self, submission):
        if not submission.link_flair_css_class:
            xbox = re.compile(
                r'''(?:\W|^)(?:xbox|360|xbla|ps3|playstation|ps4|xbone)(?:\W|$)''', re.I)
            pe = re.compile(
                r'''(?:\W|^)(?:(?:MC)?PE|Pocket Edition)(?:\W|$)''', re.I)
            if xbox.search(submission.title):
                p("Giving {} xbox flair...".format(
                    submission.name), color_seed=submission.name, end='')
                flair = 'xbox'
            elif pe.search(submission.title):
                p("Giving {} pe flair...".format(
                    submission.name), color_seed=submission.name, end='')
                flair = 'pe'
            else:
                p("Giving {} pc flair...".format(
                    submission.name), color_seed=submission.name, end='')
                flair = 'pc'
            submission.set_flair(flair_css_class=flair, flair_text=flair)


def main():
    sleep_time = 60 * 3
    r = praw.Reddit(USERAGENT, handler=MultiprocessHandler())
    r.login(USERNAME, PASSWORD)
    imgur = Imgur(IMGUR_CLIENT_ID)
    last_status = None
    processed = {'names': [], 'authors': []}
    p('Started monitoring submissions on /r/{}.'.format(SUBREDDIT))

    filters = [
        Flair(r), BannedYoutubers(r, Youtube(cache_time=0)),  YoutubeVideo(Youtube()), Suggestion(),
        Fixed(), ServerAd(r, imgur, Youtube(cache_time=60*30)), FreeMinecraft(), AmazonReferral(),
        ShortUrl(), Failed(), Minebook(), SelfLinks(), BadWords(),
        YoutubeSpam(r, Youtube(cache_time=0)), BannedSubs(), Meme(), InaneTitle(), SpamNBan(),
        AllCaps(), FileDownload(), ChunkError(), Facebook(), Reditr(), Twitch()]

    # main loop
    while True:
        p('Getting feed...', end='')
        subreddits = r.get_subreddit(SUBREDDIT)
        modqueue = subreddits.get_mod_queue(limit=100)
        comments = subreddits.get_comments(limit=100)
        new = subreddits.get_new(limit=100)
        feed = [modqueue, comments, new]
        status = sidebarUpdater()
        p('Checking if sidebar needs to be updated...', end='')
        if status:
            if last_status:
                if status != last_status:
                    p('sidebar contents changed, updating sidebar...', end='')
                    regex = r'''{}.*?{}'''.format(
                        re.escape(SIDEBAR_TAGS['start']), re.escape(SIDEBAR_TAGS['stop']))
                    text = SIDEBAR_TAGS['start'] + status + SIDEBAR_TAGS['stop']
                    sidebar = subreddits.get_wiki_page('config/sidebar')
                    sidebar_text = sidebar.content_md
                    to_replace = (('&amp;', '&'), ('&gt;', '>'), ('&lt;', '<'))
                    for i in to_replace:
                        sidebar_text = sidebar_text.replace(*i)
                    replace = re.findall(regex, sidebar_text, re.DOTALL)[0]
                    sidebar_text = sidebar_text.replace(replace, text)
                    sidebar.edit(
                        content=sidebar_text, reason='automated edit {}'.format(time.time()))
            last_status = status
        for listing in feed:
            for item in listing:
                if item.name not in processed['names']:
                    p('Processing {}'.format(item.id), color_seed=item.name, end="")
                    for f in filters:
                        processed['names'].append(item.name)
                        # Reddit's api is still a little weird here. Things are None if they're not
                        # removed by anyone, but they're True if the spam filter removed it.
                        # otherwise, it's the username of the mod.
                        if item.banned_by is not None and item.banned_by is not True:
                            break
                        if item.author and item.author.name in (USERNAME, 'TweetPoster'):
                            break
                        if item.approved_by:
                            break
                        if f.runFilter(item):
                            if f.nuke:
                                if f.action == 'remove':
                                    item.remove()
                                if f.action == 'spammed':
                                    item.remove(spam=True)
                                if f.action == 'report':
                                    item.report()
                                try:
                                    item.hide()
                                except AttributeError:
                                    pass

                            if f.comment:
                                comment = item.add_comment(f.comment)
                                comment.distinguish()
                            if f.report_subreddit:
                                r.submit(
                                    f.report_subreddit,
                                    '{} {}'.format(item.author.name, f.tag),
                                    url=item.author._url)
                            if f.ban and item.author.name not in processed['authors']:
                                p(
                                    'Banning http://reddit.com/u/{}'.format(item.author.name),
                                    color_seed=item.author.name)
                                subreddits.add_ban(
                                    item.author, note="automated ban: {}: {}".format(
                                        f.log_text, item.permalink))
                                processed['authors'].append(item.author.name)
                            break

        for i in range(sleep_time):
            p('Next scan in {} seconds...'.format(sleep_time - i), end='')
            time.sleep(1)

if __name__ == '__main__':
    signal.signal(signal.SIGINT, sigint_handler)
    main()
