from luxon import register_resource
from luxon.utils.http import request
from luxon.exceptions import AccessDenied
from luxon.constants import TEXT_HTML
from luxon.utils.encoding import if_bytes_to_unicode
import re

sql_injection = re.compile(r'^INSERT|UPDATE|SELECT.*$')

def scan(dictionary):
    for key in dictionary:
        if sql_injection.match(if_bytes_to_unicode(dictionary[key])):
            return False
    return True

@register_resource([ 'GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
                   'regex:^.*$')
def proxy(req, resp):
    to = 'http://www.google.com'
    relative_uri = req.relative_uri
    remote = to + relative_uri
    relative_uri = req.relative_uri
    if not scan(req.query_params) or not scan(req.form_dict):
        resp.content_type = TEXT_HTML
        raise AccessDenied('no sql injection please')

    response = request(req.method, remote, req.read())

    for header in response.headers:
        if header.lower() != 'content-encoding':
            resp.set_header(header, response.headers[header])
        if header.lower() == 'content-type':
            resp.content_type = response.headers[header]
    return response.body
