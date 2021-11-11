from django.test import Client
from django.db import connection

# Create your tests here.
# Please view: https://docs.djangoproject.com/en/3.2/topics/testing/overview/
c = Client()

# Sample check that you can access website
response = c.get("/gift/")
assert(response.status_code == 200)

# 1- Write the test confirming XSS vulnerability is fixed

# 2- Write the test confirming CSRF vulnerability is fixed

# 3- Write the test confirming SQL Injection attack is fixed
