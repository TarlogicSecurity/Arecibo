#!/usr/bin/python

from sys import stdin, stdout, stderr, exit
import string, random, hashlib, time, json, os

import sqlite3
from flask import Flask, request, send_file, Response
from flask_restful import Resource, Api



'''''''''''''''''''''''''''''''''''''''''''''''''''''
                Configuration
'''
FLASK_LISTEN_PORT    = 5000
DEBUG_MODE           = False
DEFAULT_RESP_BODY    = "It works!".encode("base64")
DEFAULT_RESP_HEADERS = {"Server": "Apache"}
DEFAULT_RESP_STATUS  = 200

''''''''''''''''''''''''''''''''''''''''''''''''''''''


#
# Generate random hex string
#
def hexGenerator():
    return hashlib.md5(''.join([random.choice(string.ascii_letters + string.digits) for n in xrange(32)])).hexdigest()

#
# Get client IP address
#
def get_real_ip_address():
    # If reverse proxied, return value of X-Real-IP header
    real_ip = request.headers.get('X-Real-IP', 'unknown')
    return request.remote_addr if request.remote_addr != '127.0.0.1' else real_ip



class createDnsToken(Resource):
    def get(self):
        htoken = hexGenerator()
        while True:
            try:
                c.execute('''INSERT INTO dnshextokens VALUES (?, ?, ?)''', (htoken, time.time(), get_real_ip_address()))
                conn.commit()
                break
            except sqlite3.IntegrityError:
                stderr.write("[-] Duplicated DnsToken! Getting new one\n")
                stderr.flush()
                pass
            except:
                return {'error':'Could not create dnshextoken'}
        return {'htoken' : htoken}


class retrieveDnsHits(Resource):
    def get(self, htoken):
        hits = c.execute('''SELECT * FROM dnshits WHERE htoken=?''', (htoken,))
        return {'hits' : [dict(hit) for hit in hits]}


class retrieveDnsHitsDump(Resource):
    def get(self, htoken):
        hits = c.execute('''SELECT data FROM dnshits WHERE htoken=?''', (htoken,))
        res = ''.join(hit['data'] for hit in hits)
        return {'dump' : res}


class createHttpToken(Resource):
    def insertDb(self, body=DEFAULT_RESP_BODY, headers=DEFAULT_RESP_HEADERS, status=DEFAULT_RESP_STATUS):
        htoken = hexGenerator()
        while True:
            try:
                c.execute('''INSERT INTO httphextokens VALUES (?,?,?,?,?,?)''', (htoken, time.time(), body, json.dumps(headers), status, get_real_ip_address()))
                conn.commit()
                break
            except sqlite3.IntegrityError:
                stderr.write("[-] Duplicated HttpToken! Getting new one\n")
                stderr.flush()
                pass
            except:
                return {'error':'Could not create dnshextoken'}
        return {'htoken' : htoken}

    def get(self):
        return self.insertDb()

    def post(self):
        data = request.get_json()

        body    = data.get('body', DEFAULT_RESP_BODY)
        headers = data.get('headers', DEFAULT_RESP_HEADERS)
        status  = data.get('status', DEFAULT_RESP_STATUS)

        return self.insertDb(body, headers, status)


class hitHttp(Resource):
    def hit(self, htoken):
        c.execute('''SELECT * FROM httphextokens WHERE htoken=?''', (htoken,))
        token = c.fetchone()
        if not token:
            resp = Response({'error' : 'invalid token'}, status=404)
            for key, value in DEFAULT_RESP_HEADERS.items():
                resp.headers[key] = value
            return resp

        c.execute('''
            INSERT INTO httphits(htoken, timestamp, get, post, headers, ip_address)
            VALUES (?,?,?,?,?,?)
            ''',
            (htoken, time.time(), json.dumps(request.args), json.dumps(request.form), json.dumps(dict(request.headers)), get_real_ip_address())
        )
        conn.commit()

        resp = Response(token['resp_body'].decode("base64"), status=token['status'])
        for key, value in json.loads(token['resp_headers']).items():
            resp.headers[key] = value
        return resp

    def get(self, htoken):
        return self.hit(htoken)

    def post(self, htoken):
        return self.hit(htoken)


class retrieveHttpHits(Resource):
    def get(self, htoken):
        res = []
        for hit in c.execute('''SELECT * FROM httphits WHERE htoken=?''', (htoken,)):
            res.append({
                'htoken': hit['htoken'],
                'timestamp' : hit['timestamp'],
                'get' : json.loads(hit['get']),
                'post' : json.loads(hit['post']),
                'headers' : json.loads(hit['headers']),
                'ip_address' : hit['ip_address']
            })
        return {'hits' : res}


class uploadFile(Resource):
    def post(self):
        if 'x-file' not in request.files:
            return {'error':'invalid'}, 400

        file = request.files['x-file']
        if file.filename == '':
            return {'error':'empty'}, 400

        htoken = hexGenerator()
        filename = hashlib.md5(htoken).hexdigest()
        file.save("/tmp/" + filename)
        return {'htoken' : htoken}


class downloadFile(Resource):
    def get(self, htoken):
        filename = hashlib.md5(htoken).hexdigest()
        try:
            data = send_file("/tmp/" + filename, attachment_filename=filename)
        except Exception as e:
            return {'error':'Not found'}, 404

        if 'destroy' in request.args:
            os.remove("/tmp/" + filename)

        return data


class showIP(Resource):
    def get(self):
        return {'ip' : get_real_ip_address()}




if __name__ == '__main__':

    # Create database
    try:
        stderr.write("[+] Trying to set up SQLite Database...\n")
        conn = sqlite3.connect('database.db', check_same_thread=False, timeout=1)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.executescript('''
            CREATE TABLE IF NOT EXISTS dnshextokens (
                htoken PRIMARY KEY,
                timestamp,
                ip_address
             );

            CREATE TABLE IF NOT EXISTS dnshits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                htoken,
                timestamp,
                data,
                FOREIGN KEY(htoken) REFERENCES dnshextokens(htoken)
            );

            CREATE TABLE IF NOT EXISTS httphextokens (
                htoken,
                timestamp,
                resp_body,
                resp_headers,
                status,
                ip_address
            );

            CREATE TABLE IF NOT EXISTS httphits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                htoken,
                timestamp,
                post,
                get,
                headers,
                ip_address,
                FOREIGN KEY(htoken) REFERENCES dnshextokens(htoken)
            );
            ''')

        conn.commit()
        stderr.write("[+] Database UP and running!\n")
        stderr.flush()
    except Exception as e:
        stderr.write(str(e))
        stderr.write("[!] Error: database is not up!\n")
        stderr.flush()
        exit(1)


    app = Flask("arecibo")
    api = Api(app)

    # DNS hits
    api.add_resource(createDnsToken, "/generatedns")
    api.add_resource(retrieveDnsHits, "/hitsdns/<string:htoken>")
    api.add_resource(retrieveDnsHitsDump, "/dumpdns/<string:htoken>")

    # HTTP hits
    api.add_resource(createHttpToken, "/generatehttp")
    api.add_resource(hitHttp, "/h/<string:htoken>")
    api.add_resource(retrieveHttpHits, "/hitshttp/<string:htoken>")

    # Other
    api.add_resource(uploadFile, "/upload")
    api.add_resource(downloadFile, "/download/<string:htoken>")
    api.add_resource(showIP, "/ip")

    app.run(debug=DEBUG_MODE, port=FLASK_LISTEN_PORT)
