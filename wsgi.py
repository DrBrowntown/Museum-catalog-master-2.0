WSGI file

import sys
import logging

logging.basicConfig(stream=sys.stderr)
sys.path.insert(0, '/var/www/itemsCatalog/Museum-catalog-master-2.0')

from application import app as application
application.secret_key='super_secret_key'