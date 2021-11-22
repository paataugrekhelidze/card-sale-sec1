from django.test import Client, TestCase
from . import models
from bs4 import BeautifulSoup

class AttackTestCase(TestCase):
    def setUp(self):
        models.Product.objects.create(product_id = 1, 
                                product_name = "NYU Apparel Card", 
                                product_image_path = "/images/product_1.jpg",
                                recommended_price = 95,
                                description = "Use this card to buy NYU Clothing!")
        
        # register user
        self.client.post('/register', {"uname" : "admin", 
                                    "pword" : "my_secret",
                                    "pword2" : "my_secret"})



    # 1- Write the test confirming XSS vulnerability is fixed
    # if we execute /buy.html?director=<script>alert('xss');</script>
    # the script should not escape and beautifulsoup should not be able to find the script in HTML
    # it should be modified by django builtin xss protection
    # if the script escaped the protection then it will be a first script occurence and will be equal to what we provided in the query
    def test_xss(self):
        """test xss attack"""
        xss = """<script>alert('xss');</script>"""
        response = self.client.get("""/buy?director=%s""" % xss)
        soup = BeautifulSoup(response.content, features="html.parser")      
        self.assertNotEqual(str(soup.find('script')), xss) 
    
    
    # 2- Write the test confirming CSRF vulnerability is fixed
    # gift a card and enforce csrf check. Should get status = 200 only when csrf token is provided otherwise 403
    def test_csrf(self):
        # force request to check for csrf
        client = Client(enforce_csrf_checks=True)
        data = {"username" : "admin", "amount" : "100"}
        get_response = client.get('/gift/0') # get a fresh form
        response = client.post('/gift/0', data) # will not be permitted since csrf token is missing
        self.assertEqual(response.status_code, 403) 
        # add a token to params
        data['csrfmiddlewaretoken'] = '%s' % get_response.context['csrf_token']
        response = client.post('/gift/0', data) # will work becaus the token has been provided
        self.assertEqual(response.status_code, 200) 

    # 3- Write the test confirming SQL Injection attack is fixed
    # submit .gftcrd with signature value that injects malicious sql.
    def test_sql(self):     
        
        self.client.login(username='admin', password='my_secret')

        hash_pass = models.User.objects.get(username="admin").password
        with open('attack.gftcrd') as fp:
            response = self.client.post('/use', {"card_supplied" : "test",
                                                "card_data" : fp})
        soup = BeautifulSoup(response.content, features="html.parser")     
        self.assertNotEqual(hash_pass in str(soup.find("p")), True) 
