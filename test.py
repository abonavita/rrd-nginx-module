#!/usr/bin/python
import httplib
import urllib
import unittest
import time

class TestMethods(unittest.TestCase):

    def test_POST_n_GET(self):
        # POST then GET fails sometimes.
        self.test_POST()
        self.test_GET()

    def test_POST_show_buffers(self):
        #  Request specially crafted to produce 2 buffers in the body received
        # handler (one with the beginning of the entity read with the headers
        # and one with the rest of the body).
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
        self.assertEqual(response.status, 500)
        data = response.read();
        conn.close()
        self.assertRegexpMatches(data, "Problem");

if __name__ == '__main__':
    unittest.main()
