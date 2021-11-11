# Homework 3: Buggiest Web Application

## Introduction

Unfortunately it seems your company never learns. Yet again the company
has decided to cut costs and hire Shoddycorp's Cut-Rate Contracting to 
write another program. But after all, your company insists, their *real*
strength is websites, and this time they were hired to create a high 
quality website. As usual, they did not live up to that promise, and
are not answering calls or emails yet again. Just like last time, the
task of cleaning up their mess falls to you.

The project Shoddycorp's Cut-Rate Contracting was hired to create a 
website that facilitated the sale, gifting, and use of gift cards.
They seemed to have delivered on *most* of the bare functionality of
the project, but the code is not in good shape. Luckily Kevin Gallagher
(KG) has read through the code already and left some comments around
some of the lines that concern him most. Comments not prefaced by KG were
likely left by the original author. Like with all of Shoddycorp's
Cut-Rate Contracting deliverables, this is not code you would like to
mimic in any way.

## Setting up Your Environment

In order to complete this assignment you will need the git VCS, Travis, 
python 3 and the Django web framework. You can install Django using the 
following command:

```
sudo apt-get update
sudo apt-get install python3-pip
sudo apt-get install sqlite3
sudo pip3 install django
```
NOTE: It is better practice doing this within a virtual environment and 
not use sudo, however, learning virtual environments adds a learning curve that is not part of the class. If you already know how to
do this, we recommend the virtual environment approach.

Some additional tools that may be useful for this assignment (but are
not necessary) are sqlite, burp suite, the python requests library,
and the web development console of your favorite browser. If you are
running a \*NIX system, these tools should be pre-installed and/or
available in your distribution's package manager. Like in the last
assignment we will not be checking for git best practices like writing good
commit messages. However, we will be checking for signed commits, since
they are security relevant. Additionally, it is in your best interest to
continue to follow git best practices.

When you are ready to begin the project, please create a repository 
on GitHub for your second assignment. Like before, be sure to make 
the repository **private**. Create a travis.yml file, which you will 
use to test your program later.

## How to get this working from Google Cloud
### Create an SSH Key pair
Note: Swap my UNI with yours  
`ssh-keygen -t rsa -f ~/.ssh/security1 -C MY_UNI`  
`chmod 400 ~/.ssh/security1`

where of course MY_UNI is your UNI, or any username you wish to use on your virtual
machine.
The ssh-keygen command will create a private key file at `~/.ssh/security1` and
a corresponding public key file at `~/.ssh/security1.pub`. 
The chmod command restricts
the permissions on the private key which must be kept secret on your 
local  machine so that only your user (and/or root) can view it.

### Windows ONLY
Windows users on MobaXTerm will need to start the ssh agent before
running the next step. Execute
`eval ‘ssh-agent -s’`  
If after running this command, you receive the error “Could not open a connection to
your authentication agent.” on running the next step, execute the following:  
`ssh-agent -s`  
And then copy-paste the output of the above command into your command prompt.
You will need to start the ssh-agent every time you wish to connect to your virtual
machine.

### From your Linux Device/Windows Device (Not Google Cloud VM)
You must also add the private key to your ssh-agent:  
`ssh-add ~/.ssh/security1`

### Add SSH Key to VM
To add the public SSH key to your Google Cloud project, first navigate to “Compute
Engine”, then “Metadata” using the navigation bar on the left side of the screen. You
may need to wait here while Compute Engine starts up for the first time.

Select “SSH Keys” and then [”Add SSH Keys”](google_cloud_setup.png).

Paste the entire contents of your public key file (~/.ssh/security1.pub) into the
text box (you can open the .pub file in a text editor to get its contents). The key you
paste should begin with “ssh-rsa”. When you paste your public key, it automatically fills
in the “Username” field, which is the login username associated with the public key. You
can change the “Username” field by modifying the very last part of the public key that
you pasted. Make sure to save the SSH key when you are satisfied.

`ssh -L 8000:127.0.0.1:8000 <UNI>@<Google-External-IP>`  
`ssh -L 8000:127.0.0.1:8000 afq2101@35.232.152.230`

Alternatively, you can run this from a Linux VM.

## Auditing and Test Cases

Start off by copying the files from this repository into your own, and
add them to git. The files and directories you need are:

```
GiftcardSite LegacySite images templates manage.py
```

After you copy these directories and files over, be sure to generate 
the database that django relies on. This can be done by running the commands:

```
python3 manage.py makemigrations LegacySite
python3 manage.py makemigrations
python3 manage.py migrate
sh import_dbs.sh
```

Read through the `models.py` and `views.py` files (and the helper
functions in `extras.py`) in the LegacySite folder to get a feel 
for what the website is doing and how. You can also try running
the test server and interacting with the site by running the
following command and browsing to 127.0.0.1:8000.
```
python3 manage.py runserver
```

For this part, your job will be to find some flaws in the program, and
then create test cases that expose flaws in the program. You should
write:

1. *One* attack, that exploits a XSS (cross-site scripting) 
   vulnerability.
2. *One* attack that allows you to force another user to gift
   a gift card to your account without their knowledge.
3. *One* attack that allows you to obtain the salted password for a user
   given their username. The database should contain a user named 
   ``admin.''
4. A text file, `bugs.txt` explaining the bug triggered by each of your
   attacks, and describing any other vulnerabilities or broken 
   functionalities you came across. There are more than the bugs mentioned
   above.

These attacks can take the form of a supplied URL, a POST made to the 
web page, a gift card file, a web page, a javascript function, or some
other method of attack. To create your attacks, you may want to look at 
the HTML source code of the templates and the code of each view, and 
find a way they can be exploited. 

Finally, fix the vulnerabilities that are exploited by your attacks, 
and verify that the attacks no longer succeed on your site. You are 
allowed to use django plugins and other libraries to fix these 
vulnerabilities. To make sure that these bugs don't come up again as
the code evolves, write some test cases for django that test for 
these vulnerabilities. Then have Travis run these tests with each push.

## What to Submit

The submission should contain:

* Your .travis.yml
* `bugs.txt` that describe the bugs you found, the exploit and how you fixed it
* `LegacySite/tests.py` needs to be updated with `YOUR` tests to verify the vulnerabilities were fixed
* The codebase should be updated such that the vulnerabilities should be `fixed`
* Send me your private GitHub repository, so I can see one verified commit.
- add 'AndrewQuijano'

## Grading

Total points: 100

* 30 points for providing attack cases by filling 3 attacks (10 pts. each) in `tests.py`
* 30 points for all fixes (10 pts. each), determined via auto-grader
* 20 points for the bug writeup
* 10 points for Travis regression testing, tips will be provided in video, or check [here](https://github.com/AndrewQuijano/Treespace_REU_2017) or [here](https://github.com/AndrewQuijano/EnumMatching)
* 10 points for at least 1 signed git commit, see guide [here](https://git-scm.com/book/en/v2/Git-Tools-Signing-Your-Work)

In order for us to be able to verify that you successfully signed your commits, 
please upload an ASCII armored copy of your signing key in the root directory of your repository and name it signing_key.pub.

We will read the `bugs.txt`, this will be how you gain partial credit if needed.
As for the auto-grading, we have a `tests.py` file which would attempt to exploit and verify the vulnerability is patched.
However, secure code is thoroughly tested code, so we will expect you to provide your own tests.


## Concluding Remarks

Despite the fixes you've made, there are almost certainly still many
bugs lurking in the program. Although it is possible to get to a secure
program by repeatedly finding and fixing bugs, it's a lot of work.

Though this program may be salvageable in its current state, it would be 
better in this case to rewrite it from scratch, using proper style, 
using Django addons for security purposes, and sticking to using ORMs 
and avoiding reflected unfiltered user input to the users. The code as
it exists now is difficult to read, and therefore difficult to fix. It
also unnecessarily uses home-brewed solutions for things that can be solved
easily with common libraries or Django built-ins. This is certainly not
code that you should seek to reproduce, or use as an example of good code.

A cleanly written version of this will be released after the assignment is
over. When this is released, compare it to the code you have and see what
the differences are, and how much simpler things could be if standard
solutions were used. We suspect that the cleanly written version will be
relatively bug-free, but you are encouraged to try to attack it and
prove us wrong!

## Acknowledgement
We would like to thank Kevin Gallagher, 
Invited Assistant Professor at Instituto Superior Técnico, 
University of Lisbon for providing the assignment.