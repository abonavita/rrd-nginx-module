#!/usr/bin/python
import httplib
import urllib
import unittest
import time

class TestMethods(unittest.TestCase):

    def test_PUT(self):
        conn = httplib.HTTPConnection("localhost:8000")
        params = urllib.urlencode({'name': 'daniel'});
        conn.request("PUT", "/tutu", params)
        response = conn.getresponse()
        self.assertEqual(response.status, 405)
        data = response.read();
        conn.close()
        self.assertRegexpMatches(data, ".*support.*GET.*POST");

    def test_HEAD(self):
        conn = httplib.HTTPConnection("localhost:8000")
        conn.request("HEAD", "/tutu")
        response = conn.getresponse()
        self.assertEqual(response.status, 200)
        self.assertEqual(response.getheader("Content-Type"), "image/png")
        conn.close()

    def test_POST_bad_content_type(self):
        conn = httplib.HTTPConnection("localhost:8000")
        params = "name=daniel"
        headers = {"Content-type": "text/plain",
                   "Accept": "text/plain"}
        conn.request("POST", "/tutu", params, headers)
        response = conn.getresponse()
        self.assertEqual(response.status, 405)
        data = response.read();
        conn.close()
        self.assertRegexpMatches(data, ".*content type.*");

    def test_POST(self):
        conn = httplib.HTTPConnection("localhost:8000")
        params = urllib.urlencode({'value' : 'N:12345'})
        headers = {"Content-type": "application/x-www-form-urlencoded",
                   "Accept": "text/plain"}
        conn.request("POST", "/tutu", params, headers)
        response = conn.getresponse()
        self.assertEqual(response.status, 200)
        data = response.read();
        conn.close()
        self.assertRegexpMatches(data, "Robin");

    def test_ONE_FAILURE_FOREVER(self):
        # When an error occured, all subsequent calls will have an error.
        conn = httplib.HTTPConnection("localhost:8000")
        paramsOK = urllib.urlencode({'value' : 'N:12345'})
        headers = {"Content-type": "application/x-www-form-urlencoded",
                   "Accept": "text/plain"}
        conn.request("POST", "/tutu", paramsOK, headers)
        response = conn.getresponse()
        self.assertEqual(response.status, 200)
        data = response.read();
        self.assertRegexpMatches(data, "Robin");
        paramsKO = urllib.urlencode({'value' : 'N:whatever'})
        conn.request("POST", "/tutu", paramsKO, headers)
        response = conn.getresponse()
        self.assertEqual(response.status, 200)
        data = response.read();
        self.assertRegexpMatches(data, "Problem");
        conn.request("POST", "/tutu", paramsOK, headers)
        response = conn.getresponse()
        self.assertEqual(response.status, 200)
        data = response.read();
        self.assertRegexpMatches(data, "Robin");

    def test_GET(self):
        conn = httplib.HTTPConnection("localhost:8000")
        conn.request("GET", "/tutu")
        response = conn.getresponse()
        self.assertEqual(response.status, 200)
        data = response.read();
        conn.close()
        self.assertRegexpMatches(data, "^\x89PNG");

    def test_POST_n_GET(self):
        # POST then GET fails sometimes.
        self.test_POST()
        self.test_GET()

    def test_POST_BIG(self):
        conn = httplib.HTTPConnection("localhost", 8000, None, 20)
        params = urllib.urlencode({'value' : 'N:12:34:56:78' * 20000})
        conn.putrequest("POST", "/tutu")
        conn.putheader('Content-Type', "application/x-www-form-urlencoded")
        conn.putheader('Content-Length', str(len(params) * 2))
        conn.putheader('Accept', "text/plain")
        conn.endheaders()
        time.sleep(4)
        conn.send(params)
        time.sleep(4)
        conn.send(params)
        response = conn.getresponse()
        self.assertEqual(response.status, 200)
        data = response.read();
        conn.close()
        self.assertNotRegexpMatches(data, "Robin");

    def test_POST_show_buffers(self):
        conn = httplib.HTTPConnection("localhost", 8000, None, 20)
        params = urllib.urlencode({'value' : 'N:12345:678'+'678'*300})
        conn.putrequest("POST", "/tutu")
        conn.putheader('Content-Type', "application/x-www-form-urlencoded")
        conn.putheader('Content-Length', str(len(params)))
        conn.putheader('Accept', "text/plain")
        conn.endheaders()
        conn.send(params[0:6])
        time.sleep(1)
        conn.send(params[6:15])
        time.sleep(1)
        conn.send(params[15:])
        response = conn.getresponse()
        self.assertEqual(response.status, 200)
        data = response.read();
        conn.close()
        self.assertNotRegexpMatches(data, "Robin");

if __name__ == '__main__':
    unittest.main()
