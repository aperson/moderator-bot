import json
import urllib.request
import time
from urllib.parse import urlencode
import http.cookiejar


def _isVideo(submission):
    '''Returns video author name if this is a video'''
    if 'media' in submission:
        if submission['media'] is not None:
            if 'oembed' in submission['media']:
                if 'author_name' in submission['media']['oembed']
                    if sumbission['media']['oembed']['author_name'] is not None:
                    return submission['media']['oembed']['author_name']

def _checkProfile(self, user):
    opener = urllib.request.build_opener()
    opener.addheaders = [('User-agent', 'moderator-bot.py v2')]
    with opener.open(
        'http://www.reddit.com/user/{}/comments/.json?limit=100&sort=new'.format(user)) as w:
        comments = json.loads(w.read().decode('utf-8'))['data']['children']
    time.sleep(2)
    with opener.open(
        'http://www.reddit.com/user/{}/submitted/.json?limit=100&sort=new'.format(user)) as w:
        submitted = json.loads(w.read().decode('utf-8'))['data']['children']
        submitted.reverse()
    video_count = 0
    video_authors = set()
    video_submissions = set()
    comments_on_self = 0
    for item in submitted:
        item = item['data']
        video_author = _isVideo(item)
        if video_author:
            video_count += 1
            video_authors.add(video_author)
            video_submissions.add(item['name'])
    for item in comments:
        item = item['data']
        if item['link_id'] in video_submissions:
            comments_on_self += 1
    if len(video_authors) == 1 and video_count >= 3:
        if (((video_count + comments_on_self) / (len(comments) + len(submitted))) * 100) > 90:
            return True

_checkProfile('SethBling')
