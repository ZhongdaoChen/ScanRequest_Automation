Author: Zhongdao Chen
Date: 2017/07/20
Version: 1.0.0
Environment: Python 2.7.11

Usage: 
In terminal: python main.py

Imports: 
import urllib2
from lxml import etree
from lxml import objectify
import random
import base64
import ssl
import datetime
import xml.etree.ElementTree as ET
import time
import psycopg2
import getpass
import os
import re
import pyfpdf
import sys
import getopt

pnexpose.py is the specific implementations of all Nexpose API.
Confirm_In_DMZ.py is to make sure the requested IP belongs to one of our DMZ. 
Connector_Nexpose_Postgresql.py makes the connection with Postgresql databse.
Getter_And_Setter.py manages the globe variables.
simplify_scan_report.py simplifies the full-audit report.
