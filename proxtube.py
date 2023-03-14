#!/usr/bin/env python3
import base64
import json
import logging
import os
import io
from flask import Flask, Response
import requests
from pytube import YouTube
from Crypto.Cipher import AES

app = Flask(__name__)
lastFile = {}

def decrypt(key, data, return_str=True):
    """
    Decrypts data using key checking data integrity using the embedded MAC tag
    :param key: key to use decrypt data
    :param data: data to be decrypted
    :param return_str: should the data be changed to str
    :return: a str or bytes object
    :raises ValueError: when the encrypted data was modified post encryption
    """
    nonce = data[:16]
    tag = data[16:32]
    ciphertext = data[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
    if return_str:
        try:
            decrypted_data = str(decrypted_data, 'utf-8')
        except UnicodeError as e:
            pass
    return decrypted_data

def encrypt(key, data):
    """
    Encrypts data using key
    :param key: key to use to encrypt data
    :param data: data to be encrypted
    :return: encrypted data with nonce and MAC tag prepended
    """
    if type(data) == str:
        data = bytes(data, 'utf-8')
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    encrypted_data = cipher.nonce + tag + ciphertext
    return encrypted_data

@app.route('/<path>/direct.jpg')
def prox(path):
    path = bytes(path, 'utf-8')
    path = base64.urlsafe_b64decode(path)
    path = decrypt(b'0'*16, path)
    data = requests.get(path, allow_redirects=True).content
    data = encrypt(b'0'*16, data)
    return Response(data, mimetype='image/jpg')

@app.route('/<path>/<start>/<end>/partial.jpg')
def partial(path, start, end):
    start = int(start)
    end = int(end)
    path = bytes(path, 'utf-8')
    path = base64.urlsafe_b64decode(path)
    path = decrypt(b'0'*16, path)
    data = requests.get(path, allow_redirects=True).content[start:end]
    data = encrypt(b'0'*16, data)
    return Response(data, mimetype='image/jpg')

def excep(resp, e):
    resp['errors'].append(str(e))
    logging.exception(e)

@app.route('/<path>/tubeinfo.jpg')
def tubeinfo(path):
    path = bytes(path, 'utf-8')
    path = base64.urlsafe_b64decode(path)
    path = decrypt(b'0'*16, path)
    yt = YouTube(path)
    resp = {}
    resp['errors'] = []

    try: resp['thumbnail'] = yt.thumbnail_url
    except Exception as e: excep(resp, e)
    try: resp['title'] = yt.title
    except Exception as e: excep(resp, e)
    try: resp['description'] = yt.description
    except Exception as e: excep(resp, e)
    try: resp['length'] = yt.length #!This is in seconds
    except Exception as e: excep(resp, e)
    try: resp['views'] = yt.views
    except Exception as e: excep(resp, e)
    try: resp['author'] = yt.author
    except Exception as e: excep(resp, e)

    try:
        streams = yt.streams.otf()
        details = []
        resp['details'] = details
        for stream in streams:
            try:
                details.append({
                    "itag": stream.itag,
                    "adaptive": stream.is_adaptive,
                    "progressive": stream.is_progressive,
                    "audio": stream.includes_audio_track,
                    "video": stream.includes_video_track,
                    "filesize": stream.filesize, #!This is in bytes
                    "filename": stream.default_filename,
                    "url": stream.url
                })
            except Exception as e:
                excep(resp, e)
    except Exception as e: excep(resp, e)
    data = json.dumps(resp)
    data = encrypt(b'0'*16, data)
    return Response(data, mimetype='image/jpg')

@app.route('/<path>/tubelistinfo.jpg')
def tubelistinfo(path):
    path = bytes(path, 'utf-8')
    path = base64.urlsafe_b64decode(path)
    path = decrypt(b'0'*16, path)
    pl = Playlist(path)
    resp = {}
    resp['errors'] = []
    resp['videos'] = []
    try: resp['title'] = pl.title
    except Exception as e: excep(resp, e)
    try:
        for yt in pl.videos:
            vid = {}
            resp['videos'].append(vid)
            try: vid['thumbnail'] = yt.thumbnail_url
            except Exception as e: excep(resp, e)
            try: vid['title'] = yt.title
            except Exception as e: excep(resp, e)
            try: vid['description'] = yt.description
            except Exception as e: excep(resp, e)
            try: vid['length'] = yt.length #!This is in seconds
            except Exception as e: excep(resp, e)
            try: vid['views'] = yt.views
            except Exception as e: excep(resp, e)
            try: vid['author'] = yt.author
            except Exception as e: excep(resp, e)
            try: vid['watch_url'] = yt.watch_url
            except Exception as e: excep(resp, e)

            try:
                streams = yt.streams.otf()
                details = []
                vid['details'] = details
                for stream in streams:
                    try:
                        details.append({
                            "itag": stream.itag,
                            "adaptive": stream.is_adaptive,
                            "progressive": stream.is_progressive,
                            "audio": stream.includes_audio_track,
                            "video": stream.includes_video_track,
                            "filesize": stream.filesize, #!This is in bytes
                            "filename": stream.default_filename,
                            "url": stream.url
                        })
                    except Exception as e:
                        excep(resp, e)
            except Exception as e: excep(resp, e)
    except Exception as e: excep(resp, e)
    data = json.dumps(resp)
    data = encrypt(b'0'*16, data)
    return Response(data, mimetype='image/jpg')

@app.route('/<path>/<int:itag>/<int:start>/<int:end>/tubechunk.jpg')
def tubechunk(path, itag, start, end):
    itag = int(itag)
    start = int(start)
    end = int(end)
    path = bytes(path, 'utf-8')
    path = base64.urlsafe_b64decode(path)
    path = decrypt(b'0'*16, path)
    if lastFile.get('path') == path and lastFile.get('itag') == itag and os.path.exists('tmp.bin'):
        with open('tmp.bin', 'rb') as fp:
            fp.read(start)
            data = fp.read(end-start)
    else:
        yt = YouTube(path)
        data = io.BytesIO()
        stream = yt.streams.get_by_itag(itag)
        stream.stream_to_buffer(data)
        data.seek(0)
        data = data.read()
        if len(data) < 150 * 1000 * 1000:
            lastFile['path'] = path
            lastFile['itag'] = itag
            with open('tmp.bin', 'wb') as fp: fp.write(data)
        data = data[start:end]
    data = encrypt(b'0'*16, data)
    return Response(data, mimetype='image/jpg')

# curl -H 'Snap-Device-Series: 16' http://api.snapcraft.io/v2/snaps/info/chromium >> chromium.info
@app.route('/<path>/snap.jpg')
def snap(path):
    path = bytes(path, 'utf-8')
    path = base64.urlsafe_b64decode(path)
    path = decrypt(b'0'*16, path)
    data = requests.get(f"http://api.snapcraft.io/v2/snaps/info/{path}", headers={"Snap-Device-Series":16}, allow_redirects=True).content
    data = encrypt(b'0'*16, data)
    return Response(data, mimetype='image/jpg')

@app.route('/logs.jpg')
def logs():
    if os.path.exists('proxtube.log'):
        return Response(open('proxtube.log').read(), mimetype='image/jpg')
    return Response(b'', mimetype='image/jpg')


if __name__ == "__main__":
    app.run(host="::", port=int(os.environ.get('PORT', 8100)), debug=True)
