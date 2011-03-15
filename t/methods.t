use Test::Nginx::Socket;
use URI::Escape;

repeat_each(1);

plan tests => repeat_each() * (2 * blocks());

run_tests();

__DATA__

=== TEST 1: PUT is not allowed
--- config
    location /rrd/taratata {
        rrd /var/rrd/taratata.rrd;
    }
--- request
PUT /rrd/taratata
name=daniel
--- response_body_like: support.*GET.*POST
--- error_code: 405

=== TEST 2: HEAD is OK and returns image/png
--- config
    location /rrd/taratata {
        rrd /var/rrd/taratata.rrd;
    }
--- request
    HEAD /rrd/taratata
--- response_headers_like
Content-Type:image/png
--- error_code: 200

=== TEST 3: POST bad content type
--- config
    location /rrd/taratata {
        rrd /var/rrd/taratata.rrd;
    }
--- more_headers
Content-Type: text/plain
--- request
POST /rrd/taratata
--- response_body_like: content type
--- error_code: 405

=== TEST 4: POST
The main case (when everything submitted is GOOD and the DB should be updated).
--- config
    location /rrd/taratata {
        rrd /var/rrd/taratata.rrd;
    }
--- more_headers
Content-type: application/x-www-form-urlencoded
--- request eval
use URI::Escape;
"POST /rrd/taratata
value=".uri_escape("N:12345")
--- response_body_like: go round.*Robin
--- error_code: 200

=== TEST 5 : GET
The main case (when the request is OK and you get a PNG file).
--- config
    location /rrd/taratata {
        rrd /var/rrd/taratata.rrd;
    }
--- request
GET /rrd/taratata
--- response_body_like: ^\x89PNG
--- error_code: 200

=== TEST 6 : GET with cache control
Used to fail because of a memory allocation problem
--- config
    location /rrd/taratata {
        rrd /var/rrd/taratata.rrd;
    }
--- request
GET /rrd/taratata
--- more_headers
Cache-Control: max-age=0
--- response_body_like: ^\x89PNG
--- error_code: 200

=== Test 7 : POST BIG
POST a big enough entity body with delays to trigger packet fragmentation and
creation of temp file for body.
--- config
    location /rrd/taratata {
        rrd /var/rrd/taratata.rrd;
    }
--- more_headers
Content-type: application/x-www-form-urlencoded
--- request eval
use URI::Escape;
"POST /rrd/taratata
value=".(uri_escape("N:12:34:56:78")x20000)."value="
       .(uri_escape("N:12:34:56:78")x20000)
--- raw_request_middle_delay
1
--- response_body_like: Problem
--- error_code: 500

=== TEST 8 : one failure is forever
Used to be a problem because the rrd library was not called properly
(missing rrd_clear_error call).
--- config
    location /rrd/taratata {
        rrd /var/rrd/taratata.rrd;
    }
--- more_headers
Content-type: application/x-www-form-urlencoded
--- pipelined_requests eval
use URI::Escape;
["POST /rrd/taratata
value=".uri_escape("N:12345"), "POST /rrd/taratata
value=".uri_escape("N:whatever"), "POST /rrd/taratata
value=".uri_escape("N:12345")]
--- response_body_like: Robin.*Problem.*Robin
--- error_code: 200

=== TEST 9: POST n GET
Sometimes it failed. Or so I thought. The problem was actually with
cache-control (see above).
--- config
    location /rrd/taratata {
        rrd /var/rrd/taratata.rrd;
    }
--- more_headers
Content-type: application/x-www-form-urlencoded
--- pipelined_requests eval
["POST /rrd/taratata
value=N%3A12345", "GET /rrd/taratata"]
--- response_body_like: go round.*Robin.*\x89PNG
--- error_code: 200

=== TEST 10: POST show buffers
Request specially crafted to produce 2 buffers in the body received
handler (one with the beginning of the entity read with the headers
and one with the rest of the body).
--- config
    location /rrd/taratata {
        rrd /var/rrd/taratata.rrd;
    }
--- raw_request eval
use URI::Escape;
my $val="value=N%3A12345%3A678".("678"x300);
["POST /rrd/taratata HTTP/1.1\r
Host: localhost\r
Connection: Close\r
Content-Type: application/x-www-form-urlencoded\r
Content-Length:".length($val)."\r\n\r\n",
substr($val, 0, 6),
substr($val, 6, 15),
substr($val, 21)]
--- raw_request_middle_delay
1
--- response_body_like: Problem .*updating
--- error_code: 500
