# abdulisadmin
AbdulIsAdmin is a SQL injection tool to Automate testing for discovering SQL injection vulnerable Admin Panels.
This tool automates SQLi Payloads and checks which payloads are exploitable and the website is vulberable to.
The data is dumped in the folder created in the same directory by targetname (example.com) with Target informaation, Exploitable Payloads and Non Exploitable Payloads

USAGE:
python abdulisadmin.py -u "URL_HERE" -data "POST_DATA_HERE" -cookies "COOKIES_HERE_IF_ANY"

OR

python abdulisadmin.py
Enter URL: URL_HERE
Enter POST DATA: POST_DATA_HERE
Enter Cookies: COOKIES_HERE_IF_ANY
